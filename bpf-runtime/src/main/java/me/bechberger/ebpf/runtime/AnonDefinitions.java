/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with anon
 */
@java.lang.SuppressWarnings("unused")
public final class AnonDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__anon_inode_getfile((const u8 *)$arg1, (const struct file_operations *)$arg2, $arg3, $arg4, (const struct inode *)$arg5, $arg6)")
  public static Ptr<file> __anon_inode_getfile(String name, Ptr<file_operations> fops, Ptr<?> priv,
      int flags, Ptr<inode> context_inode, boolean make_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __anon_vma_interval_tree_augment_rotate(Ptr<rb_node> rb_old,
      Ptr<rb_node> rb_new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __anon_vma_interval_tree_remove(Ptr<anon_vma_chain> node,
      Ptr<rb_root_cached> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<anon_vma_chain> __anon_vma_interval_tree_subtree_search(
      Ptr<anon_vma_chain> node, @Unsigned long start, @Unsigned long last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __anon_vma_prepare(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long anon_enabled_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("anon_enabled_store($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static @OriginalName("ssize_t") long anon_enabled_store(Ptr<kobject> kobj,
      Ptr<kobj_attribute> attr, String buf, @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long anon_fault_alloc_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long anon_fault_fallback_charge_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long anon_fault_fallback_show(Ptr<kobject> kobj,
      Ptr<kobj_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("anon_inode_create_getfd((const u8 *)$arg1, (const struct file_operations *)$arg2, $arg3, $arg4, (const struct inode *)$arg5)")
  public static int anon_inode_create_getfd(String name, Ptr<file_operations> fops, Ptr<?> priv,
      int flags, Ptr<inode> context_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("anon_inode_create_getfile((const u8 *)$arg1, (const struct file_operations *)$arg2, $arg3, $arg4, (const struct inode *)$arg5)")
  public static Ptr<file> anon_inode_create_getfile(String name, Ptr<file_operations> fops,
      Ptr<?> priv, int flags, Ptr<inode> context_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("anon_inode_getattr($arg1, (const struct path *)$arg2, $arg3, $arg4, $arg5)")
  public static int anon_inode_getattr(Ptr<mnt_idmap> idmap, Ptr<path> path, Ptr<kstat> stat,
      @Unsigned int request_mask, @Unsigned int query_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("anon_inode_getfd((const u8 *)$arg1, (const struct file_operations *)$arg2, $arg3, $arg4)")
  public static int anon_inode_getfd(String name, Ptr<file_operations> fops, Ptr<?> priv,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("anon_inode_getfile((const u8 *)$arg1, (const struct file_operations *)$arg2, $arg3, $arg4)")
  public static Ptr<file> anon_inode_getfile(String name, Ptr<file_operations> fops, Ptr<?> priv,
      int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("anon_inode_getfile_fmode((const u8 *)$arg1, (const struct file_operations *)$arg2, $arg3, $arg4, $arg5)")
  public static Ptr<file> anon_inode_getfile_fmode(String name, Ptr<file_operations> fops,
      Ptr<?> priv, int flags, @Unsigned @OriginalName("fmode_t") int f_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int anon_inode_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("anon_inode_make_secure_inode($arg1, (const u8 *)$arg2, (const struct inode *)$arg3)")
  public static Ptr<inode> anon_inode_make_secure_inode(Ptr<super_block> sb, String name,
      Ptr<inode> context_inode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int anon_inode_setattr(Ptr<mnt_idmap> idmap, Ptr<dentry> dentry, Ptr<iattr> attr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String anon_inodefs_dname(Ptr<dentry> dentry, String buffer, int buflen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int anon_inodefs_init_fs_context(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void anon_pipe_buf_release(Ptr<pipe_inode_info> pipe, Ptr<pipe_buffer> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean anon_pipe_buf_try_steal(Ptr<pipe_inode_info> pipe, Ptr<pipe_buffer> buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void anon_pipe_put_page(Ptr<pipe_inode_info> pipe, Ptr<page> page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long anon_pipe_read(Ptr<kiocb> iocb, Ptr<iov_iter> to) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long anon_pipe_write(Ptr<kiocb> iocb, Ptr<iov_iter> from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int anon_transport_class_register(Ptr<anon_transport_class> atc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void anon_transport_class_unregister(Ptr<anon_transport_class> atc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int anon_transport_dummy_function(Ptr<transport_container> tc, Ptr<device> dev,
      Ptr<device> cdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int anon_vma_clone(Ptr<vm_area_struct> dst, Ptr<vm_area_struct> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int anon_vma_compatible(Ptr<vm_area_struct> a, Ptr<vm_area_struct> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void anon_vma_ctor(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int anon_vma_fork(Ptr<vm_area_struct> vma, Ptr<vm_area_struct> pvma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void anon_vma_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void anon_vma_interval_tree_insert(Ptr<anon_vma_chain> node,
      Ptr<rb_root_cached> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<anon_vma_chain> anon_vma_interval_tree_iter_first(Ptr<rb_root_cached> root,
      @Unsigned long first, @Unsigned long last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<anon_vma_chain> anon_vma_interval_tree_iter_next(Ptr<anon_vma_chain> node,
      @Unsigned long first, @Unsigned long last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void anon_vma_interval_tree_remove(Ptr<anon_vma_chain> node,
      Ptr<rb_root_cached> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("anon_vma_name_alloc((const u8 *)$arg1)")
  public static Ptr<anon_vma_name> anon_vma_name_alloc(String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void anon_vma_name_free(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 locked; u8 pending; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_arch_spinlock_t_and_anon_member_of_qspinlock_and_anon_member_of_rqspinlock_t extends Struct {
    public char locked;

    public char pending;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { int counter; } val; struct { u8 locked; u8 pending; }; struct { short unsigned int locked_pending; short unsigned int tail; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_arch_spinlock_t_and_anon_member_of_qspinlock_and_anon_member_of_rqspinlock_t extends Union {
    public atomic_t val;

    public anon_member_of_anon_member_of_arch_spinlock_t_and_anon_member_of_qspinlock_and_anon_member_of_rqspinlock_t anon1;

    public anon_member_of_anon_member_of_arch_spinlock_t_and_anon_member_of_qspinlock_and_anon_member_of_rqspinlock_t anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 wlocked; u8 __lstate[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_arch_rwlock_t_and_anon_member_of_qrwlock extends Struct {
    public char wlocked;

    public char @Size(3) [] __lstate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { int counter; } cnts; struct { u8 wlocked; u8 __lstate[3]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_arch_rwlock_t_and_anon_member_of_qrwlock extends Union {
    public atomic_t cnts;

    public anon_member_of_anon_member_of_arch_rwlock_t_and_anon_member_of_qrwlock anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int type; struct jump_entry *entries; struct static_key_mod *next; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_static_key extends Union {
    public @Unsigned long type;

    public Ptr<jump_entry> entries;

    public Ptr<static_key_mod> next;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int cs; long long unsigned int csx; struct fred_cs fred_cs; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_user_pt_regs_t_and_anon_member_of_pt_regs extends Union {
    public @Unsigned short cs;

    public @Unsigned long csx;

    public fred_cs fred_cs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int type; struct static_call_mod *mods; struct static_call_site *sites; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_static_call_key extends Union {
    public @Unsigned long type;

    public Ptr<static_call_mod> mods;

    public Ptr<static_call_site> sites;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int u_flags; struct { int counter; } a_flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of___call_single_node extends Union {
    public @Unsigned int u_flags;

    public atomic_t a_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct __kernel_timespec *rmtp; struct old_timespec32 *compat_rmtp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nanosleep_of_anon_member_of_restart_block extends Union {
    public Ptr<__kernel_timespec> rmtp;

    public Ptr<old_timespec32> compat_rmtp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int *uaddr; unsigned int val; unsigned int flags; unsigned int bitset; long long unsigned int time; unsigned int *uaddr2; } futex; struct { int clockid; enum timespec_type type; union { struct __kernel_timespec *rmtp; struct old_timespec32 *compat_rmtp; }; long long unsigned int expires; } nanosleep; struct { struct pollfd *ufds; int nfds; int has_timeout; long unsigned int tv_sec; long unsigned int tv_nsec; } poll; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_restart_block extends Union {
    public futex_of_anon_member_of_restart_block futex;

    public nanosleep_of_anon_member_of_restart_block nanosleep;

    public poll_of_anon_member_of_restart_block poll;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct raw_spinlock rlock; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_spinlock_and_anon_member_of_spinlock_t extends Union {
    public raw_spinlock rlock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int _trapno; short int _addr_lsb; struct { u8 _dummy_bnd[8]; void *_lower; void *_upper; } _addr_bnd; struct { u8 _dummy_pkey[8]; unsigned int _pkey; } _addr_pkey; struct { long unsigned int _data; unsigned int _type; unsigned int _flags; } _perf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of__sigfault_of___sifields extends Union {
    public int _trapno;

    public short _addr_lsb;

    public _addr_bnd_of_anon_member_of__sigfault_of___sifields _addr_bnd;

    public _addr_pkey_of_anon_member_of__sigfault_of___sifields _addr_pkey;

    public _perf_of_anon_member_of__sigfault_of___sifields _perf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { int si_signo; int si_errno; int si_code; union __sifields _sifields; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_siginfo_and_anon_member_of_siginfo_t_and_anon_member_of_kernel_siginfo_and_anon_member_of_kernel_siginfo_t extends Struct {
    public int si_signo;

    public int si_errno;

    public int si_code;

    public __sifields _sifields;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long int vlag; long long unsigned int vprot; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sched_entity extends Union {
    public long vlag;

    public @Unsigned long vprot;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { spinlock ma_lock; struct { } ma_external_lock; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_maple_tree extends Union {
    public @OriginalName("spinlock_t") spinlock ma_lock;

    public lockdep_map_p ma_external_lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 insn[16]; u8 ixol[16]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_arch_uprobe extends Union {
    public char @Size(16) [] insn;

    public char @Size(16) [] ixol;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct arch_uprobe_task autask; long unsigned int vaddr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_uprobe_task extends Struct {
    public arch_uprobe_task autask;

    public @Unsigned long vaddr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct arch_uprobe_task autask; long unsigned int vaddr; }; struct { struct callback_head dup_xol_work; long unsigned int dup_xol_addr; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_uprobe_task extends Union {
    public anon_member_of_anon_member_of_uprobe_task anon0;

    public anon_member_of_anon_member_of_uprobe_task anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { void *__filler; unsigned int mlock_count; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_folio_and_anon_member_of_anon_member_of_anon_member_of_anon_member_of_page extends Struct {
    public Ptr<?> __filler;

    public @Unsigned int mlock_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct llist_node pcp_llist; unsigned int order; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_page extends Struct {
    public llist_node pcp_llist;

    public @Unsigned int order;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head lru; struct { void *__filler; unsigned int mlock_count; }; struct list_head buddy_list; struct list_head pcp_list; struct { struct llist_node pcp_llist; unsigned int order; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_page extends Union {
    public list_head lru;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_folio_and_anon_member_of_anon_member_of_anon_member_of_anon_member_of_page anon1;

    public list_head buddy_list;

    public list_head pcp_list;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_page anon4;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { union { struct list_head lru; struct { void *__filler; unsigned int mlock_count; }; struct list_head buddy_list; struct list_head pcp_list; struct { struct llist_node pcp_llist; unsigned int order; }; }; struct address_space *mapping; union { long unsigned int __folio_index; long unsigned int share; }; long unsigned int private; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_page extends Struct {
    @InlineUnion(727)
    public list_head lru;

    @InlineUnion(727)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_folio_and_anon_member_of_anon_member_of_anon_member_of_anon_member_of_page anon0$1;

    @InlineUnion(727)
    public list_head buddy_list;

    @InlineUnion(727)
    public list_head pcp_list;

    @InlineUnion(727)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_page anon0$4;

    public Ptr<address_space> mapping;

    @InlineUnion(728)
    public @Unsigned long __folio_index;

    @InlineUnion(728)
    public @Unsigned long share;

    public @Unsigned long _private;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { union { struct list_head lru; struct { void *__filler; unsigned int mlock_count; }; struct list_head buddy_list; struct list_head pcp_list; struct { struct llist_node pcp_llist; unsigned int order; }; }; struct address_space *mapping; union { long unsigned int __folio_index; long unsigned int share; }; long unsigned int private; }; struct { long unsigned int pp_magic; struct page_pool *pp; long unsigned int _pp_mapping_pad; long unsigned int dma_addr; struct { long long int counter; } pp_ref_count; }; struct { long unsigned int compound_head; }; struct { void *_unused_pgmap_compound_head; void *zone_device_data; }; struct callback_head callback_head; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_page extends Union {
    public anon_member_of_anon_member_of_page anon0;

    public anon_member_of_anon_member_of_page anon1;

    public anon_member_of_anon_member_of_page anon2;

    public anon_member_of_anon_member_of_page anon3;

    public callback_head callback_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head lru; struct { void *__filler; unsigned int mlock_count; }; struct dev_pagemap *pgmap; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_folio extends Union {
    public list_head lru;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_folio_and_anon_member_of_anon_member_of_anon_member_of_anon_member_of_page anon1;

    public Ptr<dev_pagemap> pgmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int flags; union { struct list_head lru; struct { void *__filler; unsigned int mlock_count; }; struct dev_pagemap *pgmap; }; struct address_space *mapping; union { long unsigned int index; long unsigned int share; }; union { void *private; struct { long unsigned int val; } swap; }; struct { int counter; } _mapcount; struct { int counter; } _refcount; long unsigned int memcg_data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_folio extends Struct {
    public @Unsigned long flags;

    @InlineUnion(740)
    public list_head lru;

    @InlineUnion(740)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_folio_and_anon_member_of_anon_member_of_anon_member_of_anon_member_of_page anon1$1;

    @InlineUnion(740)
    public Ptr<dev_pagemap> pgmap;

    public Ptr<address_space> mapping;

    @InlineUnion(743)
    public @Unsigned long index;

    @InlineUnion(743)
    public @Unsigned long share;

    @InlineUnion(744)
    public Ptr<?> _private;

    @InlineUnion(744)
    public swp_entry_t swap;

    public atomic_t _mapcount;

    public atomic_t _refcount;

    public @Unsigned long memcg_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long unsigned int flags; union { struct list_head lru; struct { void *__filler; unsigned int mlock_count; }; struct dev_pagemap *pgmap; }; struct address_space *mapping; union { long unsigned int index; long unsigned int share; }; union { void *private; struct { long unsigned int val; } swap; }; struct { int counter; } _mapcount; struct { int counter; } _refcount; long unsigned int memcg_data; }; struct page page; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_folio extends Union {
    public anon_member_of_anon_member_of_folio anon0;

    public page page;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int _mm_id[2]; long unsigned int _mm_ids; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_anon_member_of_folio extends Union {
    public @Unsigned @OriginalName("mm_id_t") int @Size(2) [] _mm_id;

    public @Unsigned long _mm_ids;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { int counter; } _large_mapcount; struct { int counter; } _nr_pages_mapped; struct { int counter; } _entire_mapcount; struct { int counter; } _pincount; int _mm_id_mapcount[2]; union { unsigned int _mm_id[2]; long unsigned int _mm_ids; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_folio extends Struct {
    public atomic_t _large_mapcount;

    public atomic_t _nr_pages_mapped;

    public atomic_t _entire_mapcount;

    public atomic_t _pincount;

    public @OriginalName("mm_id_mapcount_t") int @Size(2) [] _mm_id_mapcount;

    @InlineUnion(747)
    public @Unsigned @OriginalName("mm_id_t") int @Size(2) [] _mm_id;

    @InlineUnion(747)
    public @Unsigned long _mm_ids;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct anon_vma_name"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_vma_name extends Struct {
    public kref kref;

    public char @Size(0) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int vm_start; long unsigned int vm_end; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_vm_area_struct extends Struct {
    public @Unsigned long vm_start;

    public @Unsigned long vm_end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long unsigned int vm_start; long unsigned int vm_end; }; struct { long unsigned int v; } vm_freeptr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vm_area_struct extends Union {
    public anon_member_of_anon_member_of_vm_area_struct anon0;

    public freeptr_t vm_freeptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct anon_vma"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_vma extends Struct {
    public Ptr<anon_vma> root;

    public rw_semaphore rwsem;

    public atomic_t refcount;

    public @Unsigned long num_children;

    public @Unsigned long num_active_vmas;

    public Ptr<anon_vma> parent;

    public rb_root_cached rb_root;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { int counter; } mm_count; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_mm_struct extends Struct {
    public atomic_t mm_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { struct { int counter; } mm_count; }; struct maple_tree mm_mt; long unsigned int mmap_base; long unsigned int mmap_legacy_base; long unsigned int mmap_compat_base; long unsigned int mmap_compat_legacy_base; long unsigned int task_size; struct { long unsigned int pgd; } *pgd; struct { int counter; } membarrier_state; struct { int counter; } mm_users; struct mm_cid *pcpu_cid; long unsigned int mm_cid_next_scan; unsigned int nr_cpus_allowed; struct { int counter; } max_nr_cid; raw_spinlock cpus_allowed_lock; struct { long long int counter; } pgtables_bytes; int map_count; spinlock page_table_lock; struct rw_semaphore mmap_lock; struct list_head mmlist; struct rcuwait vma_writer_wait; seqcount mm_lock_seq; struct mutex futex_hash_lock; struct futex_private_hash *futex_phash; struct futex_private_hash *futex_phash_new; long unsigned int futex_batches; struct callback_head futex_rcu; struct { long long int counter; } futex_atomic; unsigned int *futex_ref; long unsigned int hiwater_rss; long unsigned int hiwater_vm; long unsigned int total_vm; long unsigned int locked_vm; struct { long long int counter; } pinned_vm; long unsigned int data_vm; long unsigned int exec_vm; long unsigned int stack_vm; long unsigned int def_flags; seqcount write_protect_seq; spinlock arg_lock; long unsigned int start_code; long unsigned int end_code; long unsigned int start_data; long unsigned int end_data; long unsigned int start_brk; long unsigned int brk; long unsigned int start_stack; long unsigned int arg_start; long unsigned int arg_end; long unsigned int env_start; long unsigned int env_end; long unsigned int saved_auxv[52]; struct percpu_counter rss_stat[4]; struct linux_binfmt *binfmt; struct { long long unsigned int ctx_id; struct { long long int counter; } tlb_gen; long unsigned int next_trim_cpumask; struct rw_semaphore ldt_usr_sem; struct ldt_struct *ldt; long unsigned int flags; struct mutex lock; void *vdso; const struct vdso_image *vdso_image; struct { int counter; } perf_rdpmc_allowed; short unsigned int pkey_allocation_map; short int execute_only_pkey; short unsigned int global_asid; _Bool asid_transition; } context; long unsigned int flags; spinlock ioctx_lock; struct kioctx_table *ioctx_table; struct task_struct *owner; struct user_namespace *user_ns; struct file *exe_file; struct mmu_notifier_subscriptions *notifier_subscriptions; long unsigned int numa_next_scan; long unsigned int numa_scan_offset; int numa_scan_seq; struct { int counter; } tlb_flush_pending; struct { int counter; } tlb_flush_batched; struct uprobes_state uprobes_state; struct { long long int counter; } hugetlb_usage; struct work_struct async_put_work; struct iommu_mm_data *iommu_mm; long unsigned int ksm_merging_pages; long unsigned int ksm_rmap_items; struct { long long int counter; } ksm_zero_pages; struct { struct list_head list; long unsigned int bitmap; struct mem_cgroup *memcg; } lru_gen; unsigned int mm_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mm_struct extends Struct {
    public anon_member_of_anon_member_of_mm_struct anon0;

    public maple_tree mm_mt;

    public @Unsigned long mmap_base;

    public @Unsigned long mmap_legacy_base;

    public @Unsigned long mmap_compat_base;

    public @Unsigned long mmap_compat_legacy_base;

    public @Unsigned long task_size;

    public Ptr<pgd_t> pgd;

    public atomic_t membarrier_state;

    public atomic_t mm_users;

    public Ptr<mm_cid> pcpu_cid;

    public @Unsigned long mm_cid_next_scan;

    public @Unsigned int nr_cpus_allowed;

    public atomic_t max_nr_cid;

    public @OriginalName("raw_spinlock_t") raw_spinlock cpus_allowed_lock;

    public @OriginalName("atomic_long_t") atomic64_t pgtables_bytes;

    public int map_count;

    public @OriginalName("spinlock_t") spinlock page_table_lock;

    public rw_semaphore mmap_lock;

    public list_head mmlist;

    public rcuwait vma_writer_wait;

    public @OriginalName("seqcount_t") seqcount mm_lock_seq;

    public mutex futex_hash_lock;

    public Ptr<futex_private_hash> futex_phash;

    public Ptr<futex_private_hash> futex_phash_new;

    public @Unsigned long futex_batches;

    public callback_head futex_rcu;

    public @OriginalName("atomic_long_t") atomic64_t futex_atomic;

    public Ptr<java.lang. @Unsigned Integer> futex_ref;

    public @Unsigned long hiwater_rss;

    public @Unsigned long hiwater_vm;

    public @Unsigned long total_vm;

    public @Unsigned long locked_vm;

    public atomic64_t pinned_vm;

    public @Unsigned long data_vm;

    public @Unsigned long exec_vm;

    public @Unsigned long stack_vm;

    public @Unsigned @OriginalName("vm_flags_t") long def_flags;

    public @OriginalName("seqcount_t") seqcount write_protect_seq;

    public @OriginalName("spinlock_t") spinlock arg_lock;

    public @Unsigned long start_code;

    public @Unsigned long end_code;

    public @Unsigned long start_data;

    public @Unsigned long end_data;

    public @Unsigned long start_brk;

    public @Unsigned long brk;

    public @Unsigned long start_stack;

    public @Unsigned long arg_start;

    public @Unsigned long arg_end;

    public @Unsigned long env_start;

    public @Unsigned long env_end;

    public @Unsigned long @Size(52) [] saved_auxv;

    public percpu_counter @Size(4) [] rss_stat;

    public Ptr<linux_binfmt> binfmt;

    public mm_context_t context;

    public @Unsigned long flags;

    public @OriginalName("spinlock_t") spinlock ioctx_lock;

    public Ptr<kioctx_table> ioctx_table;

    public Ptr<task_struct> owner;

    public Ptr<user_namespace> user_ns;

    public Ptr<file> exe_file;

    public Ptr<mmu_notifier_subscriptions> notifier_subscriptions;

    public @Unsigned long numa_next_scan;

    public @Unsigned long numa_scan_offset;

    public int numa_scan_seq;

    public atomic_t tlb_flush_pending;

    public atomic_t tlb_flush_batched;

    public uprobes_state uprobes_state;

    public @OriginalName("atomic_long_t") atomic64_t hugetlb_usage;

    public work_struct async_put_work;

    public Ptr<iommu_mm_data> iommu_mm;

    public @Unsigned long ksm_merging_pages;

    public @Unsigned long ksm_rmap_items;

    public @OriginalName("atomic_long_t") atomic64_t ksm_zero_pages;

    public lru_gen_of_anon_member_of_mm_struct lru_gen;

    public @Unsigned @OriginalName("mm_id_t") int mm_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { const struct ctl_table *ctl_table; int ctl_table_size; int used; int count; int nreg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ctl_table_header extends Struct {
    public Ptr<ctl_table> ctl_table;

    public int ctl_table_size;

    public int used;

    public int count;

    public int nreg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { const struct ctl_table *ctl_table; int ctl_table_size; int used; int count; int nreg; }; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ctl_table_header extends Union {
    public anon_member_of_anon_member_of_ctl_table_header anon0;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const struct iovec *__iov; const struct kvec *kvec; const struct bio_vec *bvec; const struct folio_queue *folioq; struct xarray *xarray; void *ubuf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_iov_iter extends Union {
    public Ptr<iovec> __iov;

    public Ptr<kvec> kvec;

    public Ptr<bio_vec> bvec;

    public Ptr<folio_queue> folioq;

    public Ptr<xarray> xarray;

    public Ptr<?> ubuf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { union { const struct iovec *__iov; const struct kvec *kvec; const struct bio_vec *bvec; const struct folio_queue *folioq; struct xarray *xarray; void *ubuf; }; long unsigned int count; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_iov_iter extends Struct {
    @InlineUnion(896)
    public Ptr<iovec> __iov;

    @InlineUnion(896)
    public Ptr<kvec> kvec;

    @InlineUnion(896)
    public Ptr<bio_vec> bvec;

    @InlineUnion(896)
    public Ptr<folio_queue> folioq;

    @InlineUnion(896)
    public Ptr<xarray> xarray;

    @InlineUnion(896)
    public Ptr<?> ubuf;

    public @Unsigned long count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct iovec __ubuf_iovec; struct { union { const struct iovec *__iov; const struct kvec *kvec; const struct bio_vec *bvec; const struct folio_queue *folioq; struct xarray *xarray; void *ubuf; }; long unsigned int count; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iov_iter extends Union {
    public iovec __ubuf_iovec;

    public anon_member_of_anon_member_of_iov_iter anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { spinlock lock; int count; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_lockref extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public int count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int lock_count; struct { spinlock lock; int count; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_lockref extends Union {
    public @Unsigned long lock_count;

    public anon_member_of_anon_member_of_lockref anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int hash; unsigned int len; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_qstr extends Struct {
    public @Unsigned int hash;

    public @Unsigned int len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int hash; unsigned int len; }; long long unsigned int hash_len; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_qstr extends Union {
    public anon_member_of_anon_member_of_qstr anon0;

    public @Unsigned long hash_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head d_lru; wait_queue_head *d_wait; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dentry extends Union {
    public list_head d_lru;

    public Ptr<@OriginalName("wait_queue_head_t") wait_queue_head> d_wait;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int ino; struct rb_node pidfs_node; struct dentry *stashed; struct pidfs_attr *attr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pid extends Struct {
    public @Unsigned long ino;

    public rb_node pidfs_node;

    public Ptr<dentry> stashed;

    public Ptr<pidfs_attr> attr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int desc_len; u8 desc[6]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_keyring_index_key extends Struct {
    public @Unsigned short desc_len;

    public char @Size(6) [] desc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int desc_len; u8 desc[6]; }; long unsigned int x; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_keyring_index_key extends Union {
    public anon_member_of_anon_member_of_keyring_index_key anon0;

    public @Unsigned long x;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head graveyard_link; struct rb_node serial_node; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_key extends Union {
    public list_head graveyard_link;

    public rb_node serial_node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int hash; long unsigned int len_desc; struct key_type *type; struct key_tag *domain_tag; u8 *description; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_key extends Struct {
    public @Unsigned long hash;

    public @Unsigned long len_desc;

    public Ptr<key_type> type;

    public Ptr<key_tag> domain_tag;

    public String description;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int non_rcu; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_cred extends Union {
    public int non_rcu;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head q_node; struct kmem_cache *__rcu_icq_cache; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_cq extends Union {
    public list_head q_node;

    public Ptr<kmem_cache> __rcu_icq_cache;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int val; } ia_uid; struct { unsigned int val; } ia_vfsuid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iattr extends Union {
    public kuid_t ia_uid;

    public @OriginalName("vfsuid_t") kuid_t ia_vfsuid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int val; } uid; struct { unsigned int val; } gid; struct { unsigned int val; } projid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kqid extends Union {
    public kuid_t uid;

    public kgid_t gid;

    public kprojid_t projid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct wait_page_queue *ki_waitq; long int (*dio_complete)(void*); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kiocb extends Union {
    public Ptr<wait_page_queue> ki_waitq;

    public Ptr<?> dio_complete;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const unsigned int i_nlink; unsigned int __i_nlink; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_inode extends Union {
    public @Unsigned int i_nlink;

    public @Unsigned int __i_nlink;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct mutex f_pos_lock; long long unsigned int f_pipe; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_file extends Union {
    public mutex f_pos_lock;

    public @Unsigned long f_pipe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct kernfs_elem_dir dir; struct kernfs_elem_symlink symlink; struct kernfs_elem_attr attr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kernfs_node extends Union {
    public kernfs_elem_dir dir;

    public kernfs_elem_symlink symlink;

    public kernfs_elem_attr attr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const const struct bin_attribute *bin_attrs*; const const struct bin_attribute *bin_attrs_new*; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_attribute_group extends Union {
    public Ptr<Ptr<bin_attribute>> bin_attrs;

    public Ptr<Ptr<bin_attribute>> bin_attrs_new;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *arg; const struct kparam_string *str; const struct kparam_array *arr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kernel_param extends Union {
    public Ptr<?> arg;

    public Ptr<kparam_string> str;

    public Ptr<kparam_array> arr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_ranges; struct range ranges[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_dev_pagemap extends Struct {
    public lockdep_map_p __empty_ranges;

    public range @Size(0) [] ranges;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct range range; struct { struct { } __empty_ranges; struct range ranges[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dev_pagemap extends Union {
    public range range;

    public anon_member_of_anon_member_of_dev_pagemap anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct vm_area_struct *vma; unsigned int gfp_mask; long unsigned int pgoff; long unsigned int address; long unsigned int real_address; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vm_fault extends Struct {
    public Ptr<vm_area_struct> vma;

    public @Unsigned @OriginalName("gfp_t") int gfp_mask;

    public @Unsigned long pgoff;

    public @Unsigned long address;

    public @Unsigned long real_address;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int sample_period; long long unsigned int sample_freq; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_event_attr extends Union {
    public @Unsigned long sample_period;

    public @Unsigned long sample_freq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int aux_start_paused; unsigned int aux_pause; unsigned int aux_resume; unsigned int __reserved_3; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_perf_event_attr extends Struct {
    public @Unsigned int aux_start_paused;

    public @Unsigned int aux_pause;

    public @Unsigned int aux_resume;

    public @Unsigned int __reserved_3;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int mem_op; long long unsigned int mem_lvl; long long unsigned int mem_snoop; long long unsigned int mem_lock; long long unsigned int mem_dtlb; long long unsigned int mem_lvl_num; long long unsigned int mem_remote; long long unsigned int mem_snoopx; long long unsigned int mem_blk; long long unsigned int mem_hops; long long unsigned int mem_rsvd; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_mem_data_src extends Struct {
    public @Unsigned long mem_op;

    public @Unsigned long mem_lvl;

    public @Unsigned long mem_snoop;

    public @Unsigned long mem_lock;

    public @Unsigned long mem_dtlb;

    public @Unsigned long mem_lvl_num;

    public @Unsigned long mem_remote;

    public @Unsigned long mem_snoopx;

    public @Unsigned long mem_blk;

    public @Unsigned long mem_hops;

    public @Unsigned long mem_rsvd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int var1_dw; short unsigned int var2_w; short unsigned int var3_w; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_sample_weight extends Struct {
    public @Unsigned int var1_dw;

    public @Unsigned short var2_w;

    public @Unsigned short var3_w;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct uid_gid_extent extent[5]; unsigned int nr_extents; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_uid_gid_map extends Struct {
    public uid_gid_extent @Size(5) [] extent;

    public @Unsigned int nr_extents;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct uid_gid_extent extent[5]; unsigned int nr_extents; }; struct { struct uid_gid_extent *forward; struct uid_gid_extent *reverse; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_uid_gid_map extends Union {
    public anon_member_of_anon_member_of_uid_gid_map anon0;

    public anon_member_of_anon_member_of_uid_gid_map anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int map_type; unsigned int key_size; unsigned int value_size; unsigned int max_entries; unsigned int map_flags; unsigned int inner_map_fd; unsigned int numa_node; u8 map_name[16]; unsigned int map_ifindex; unsigned int btf_fd; unsigned int btf_key_type_id; unsigned int btf_value_type_id; unsigned int btf_vmlinux_value_type_id; long long unsigned int map_extra; int value_type_btf_obj_fd; int map_token_fd; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_attr extends Struct {
    public @Unsigned int map_type;

    public @Unsigned int key_size;

    public @Unsigned int value_size;

    public @Unsigned int max_entries;

    public @Unsigned int map_flags;

    public @Unsigned int inner_map_fd;

    public @Unsigned int numa_node;

    public char @Size(16) [] map_name;

    public @Unsigned int map_ifindex;

    public @Unsigned int btf_fd;

    public @Unsigned int btf_key_type_id;

    public @Unsigned int btf_value_type_id;

    public @Unsigned int btf_vmlinux_value_type_id;

    public @Unsigned long map_extra;

    public int value_type_btf_obj_fd;

    public int map_token_fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int value; long long unsigned int next_key; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_attr extends Union {
    public @Unsigned long value;

    public @Unsigned long next_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int target_fd; unsigned int target_ifindex; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_attr_and_anon_member_of_link_create_of_bpf_attr_and_anon_member_of_query_of_bpf_attr extends Union {
    public @Unsigned int target_fd;

    public @Unsigned int target_ifindex;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int relative_fd; unsigned int relative_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_attr_and_anon_member_of_cgroup_of_anon_member_of_link_create_of_bpf_attr_and_netkit_of_anon_member_of_link_create_of_bpf_attr_and_tcx_of_anon_member_of_link_create_of_bpf_attr extends Union {
    public @Unsigned int relative_fd;

    public @Unsigned int relative_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int prog_cnt; unsigned int count; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_query_of_bpf_attr extends Union {
    public @Unsigned int prog_cnt;

    public @Unsigned int count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int prog_fd; unsigned int map_fd; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_link_create_of_bpf_attr extends Union {
    public @Unsigned int prog_fd;

    public @Unsigned int map_fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int iter_info; unsigned int iter_info_len; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_link_create_of_bpf_attr extends Struct {
    public @Unsigned long iter_info;

    public @Unsigned int iter_info_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int new_prog_fd; unsigned int new_map_fd; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_link_update_of_bpf_attr extends Union {
    public @Unsigned int new_prog_fd;

    public @Unsigned int new_map_fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int map_id; } map; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iter_of_anon_member_of_bpf_link_info extends Union {
    public map_of_anon_member_of_iter_of_anon_member_of_bpf_link_info_and_struct_ops_of_anon_member_of_bpf_link_info map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int file_name; unsigned int name_len; unsigned int offset; long long unsigned int cookie; long long unsigned int ref_ctr_offset; } uprobe; struct { long long unsigned int func_name; unsigned int name_len; unsigned int offset; long long unsigned int addr; long long unsigned int missed; long long unsigned int cookie; } kprobe; struct { long long unsigned int tp_name; unsigned int name_len; long long unsigned int cookie; } tracepoint; struct { long long unsigned int config; unsigned int type; long long unsigned int cookie; } event; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_event_of_anon_member_of_bpf_link_info extends Union {
    public uprobe_of_anon_member_of_perf_event_of_anon_member_of_bpf_link_info uprobe;

    public kprobe_of_anon_member_of_perf_event_of_anon_member_of_bpf_link_info kprobe;

    public tracepoint_of_anon_member_of_perf_event_of_anon_member_of_bpf_link_info tracepoint;

    public event_of_anon_member_of_perf_event_of_anon_member_of_bpf_link_info event;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int tp_name; unsigned int tp_name_len; long long unsigned int cookie; } raw_tracepoint; struct { unsigned int attach_type; unsigned int target_obj_id; unsigned int target_btf_id; long long unsigned int cookie; } tracing; struct { long long unsigned int cgroup_id; unsigned int attach_type; } cgroup; struct { long long unsigned int target_name; unsigned int target_name_len; union { struct { unsigned int map_id; } map; }; union { struct { long long unsigned int cgroup_id; unsigned int order; } cgroup; struct { unsigned int tid; unsigned int pid; } task; }; } iter; struct { unsigned int netns_ino; unsigned int attach_type; } netns; struct { unsigned int ifindex; } xdp; struct { unsigned int map_id; } struct_ops; struct { unsigned int pf; unsigned int hooknum; int priority; unsigned int flags; } netfilter; struct { long long unsigned int addrs; unsigned int count; unsigned int flags; long long unsigned int missed; long long unsigned int cookies; } kprobe_multi; struct { long long unsigned int path; long long unsigned int offsets; long long unsigned int ref_ctr_offsets; long long unsigned int cookies; unsigned int path_size; unsigned int count; unsigned int flags; unsigned int pid; } uprobe_multi; struct { unsigned int type; union { struct { long long unsigned int file_name; unsigned int name_len; unsigned int offset; long long unsigned int cookie; long long unsigned int ref_ctr_offset; } uprobe; struct { long long unsigned int func_name; unsigned int name_len; unsigned int offset; long long unsigned int addr; long long unsigned int missed; long long unsigned int cookie; } kprobe; struct { long long unsigned int tp_name; unsigned int name_len; long long unsigned int cookie; } tracepoint; struct { long long unsigned int config; unsigned int type; long long unsigned int cookie; } event; }; } perf_event; struct { unsigned int ifindex; unsigned int attach_type; } tcx; struct { unsigned int ifindex; unsigned int attach_type; } netkit; struct { unsigned int map_id; unsigned int attach_type; } sockmap; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_link_info extends Union {
    public raw_tracepoint_of_anon_member_of_bpf_link_info raw_tracepoint;

    public tracing_of_anon_member_of_bpf_link_info tracing;

    public cgroup_of_anon_member_of_bpf_link_info cgroup;

    public iter_of_anon_member_of_bpf_link_info iter;

    public netns_of_anon_member_of_bpf_link_info netns;

    public xdp_of_anon_member_of_bpf_link_info xdp;

    public map_of_anon_member_of_iter_of_anon_member_of_bpf_link_info_and_struct_ops_of_anon_member_of_bpf_link_info struct_ops;

    public netfilter_of_anon_member_of_bpf_link_info_and_netfilter_of_anon_member_of_link_create_of_bpf_attr netfilter;

    public kprobe_multi_of_anon_member_of_bpf_link_info kprobe_multi;

    public uprobe_multi_of_anon_member_of_bpf_link_info uprobe_multi;

    public perf_event_of_anon_member_of_bpf_link_info perf_event;

    public netkit_of_anon_member_of_bpf_link_info_and_tcx_of_anon_member_of_bpf_link_info tcx;

    public netkit_of_anon_member_of_bpf_link_info_and_tcx_of_anon_member_of_bpf_link_info netkit;

    public sockmap_of_anon_member_of_bpf_link_info sockmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int size; unsigned int type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_btf_type extends Union {
    public @Unsigned int size;

    public @Unsigned int type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct work_struct release_work; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bdi_writeback extends Union {
    public work_struct release_work;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int bi_cookie; unsigned int __bi_nr_segments; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bio extends Union {
    public @Unsigned @OriginalName("blk_qc_t") int bi_cookie;

    public @Unsigned int __bi_nr_segments;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head list; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_eventfs_inode_and_anon_member_of_obj_cgroup extends Union {
    public list_head list;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct page_counter swap; struct page_counter memsw; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mem_cgroup extends Union {
    public page_counter swap;

    public page_counter memsw;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct btf_field_kptr kptr; struct btf_field_graph_root graph_root; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_btf_field extends Union {
    public btf_field_kptr kptr;

    public btf_field_graph_root graph_root;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct work_struct work; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_map_and_anon_member_of_bpf_prog_aux extends Union {
    public work_struct work;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { enum bpf_arg_type arg1_type; enum bpf_arg_type arg2_type; enum bpf_arg_type arg3_type; enum bpf_arg_type arg4_type; enum bpf_arg_type arg5_type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_func_proto extends Struct {
    public bpf_arg_type arg1_type;

    public bpf_arg_type arg2_type;

    public bpf_arg_type arg3_type;

    public bpf_arg_type arg4_type;

    public bpf_arg_type arg5_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { enum bpf_arg_type arg1_type; enum bpf_arg_type arg2_type; enum bpf_arg_type arg3_type; enum bpf_arg_type arg4_type; enum bpf_arg_type arg5_type; }; enum bpf_arg_type arg_type[5]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_func_proto extends Union {
    public anon_member_of_anon_member_of_bpf_func_proto anon0;

    public bpf_arg_type @Size(5) [] arg_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct btf *btf; unsigned int btf_id; unsigned int ref_obj_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_insn_access_aux extends Struct {
    public Ptr<btf> btf;

    public @Unsigned int btf_id;

    public @Unsigned int ref_obj_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int ctx_field_size; struct { struct btf *btf; unsigned int btf_id; unsigned int ref_obj_id; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_insn_access_aux extends Union {
    public int ctx_field_size;

    public anon_member_of_anon_member_of_bpf_insn_access_aux anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct callback_head rcu; struct work_struct work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_link_and_anon_member_of_bpf_tramp_image_and_anon_member_of_uprobe extends Union {
    public callback_head rcu;

    public work_struct work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct bpf_map *map; unsigned int key; } tail_call; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_jit_poke_descriptor extends Union {
    public tail_call_of_anon_member_of_bpf_jit_poke_descriptor tail_call;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_insns; struct sock_filter insns[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_prog extends Struct {
    public lockdep_map_p __empty_insns;

    public sock_filter @Size(0) [] insns;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { } __empty_insns; struct sock_filter insns[0]; }; struct { struct { } __empty_insnsi; struct bpf_insn insnsi[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_prog extends Union {
    public anon_member_of_anon_member_of_bpf_prog anon0;

    public anon_member_of_anon_member_of_bpf_prog anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_cgroup_storage* cgroup_storage[2]; long long unsigned int bpf_cookie; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_prog_array_item extends Union {
    public Ptr<bpf_cgroup_storage> @Size(2) [] cgroup_storage;

    public @Unsigned long bpf_cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct perf_raw_frag *next; long unsigned int pad; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_raw_frag extends Union {
    public Ptr<perf_raw_frag> next;

    public @Unsigned long pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int config; long long unsigned int config1; long long unsigned int last_tag; long long unsigned int dyn_constraint; long unsigned int config_base; long unsigned int event_base; int event_base_rdpmc; int idx; int last_cpu; int flags; struct hw_perf_event_extra extra_reg; struct hw_perf_event_extra branch_reg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_hw_perf_event extends Struct {
    public @Unsigned long config;

    public @Unsigned long config1;

    public @Unsigned long last_tag;

    public @Unsigned long dyn_constraint;

    public @Unsigned long config_base;

    public @Unsigned long event_base;

    public int event_base_rdpmc;

    public int idx;

    public int last_cpu;

    public int flags;

    public hw_perf_event_extra extra_reg;

    public hw_perf_event_extra branch_reg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int config; long long unsigned int config1; long long unsigned int last_tag; long long unsigned int dyn_constraint; long unsigned int config_base; long unsigned int event_base; int event_base_rdpmc; int idx; int last_cpu; int flags; struct hw_perf_event_extra extra_reg; struct hw_perf_event_extra branch_reg; }; struct { long long unsigned int aux_config; unsigned int aux_paused; }; struct { struct hrtimer hrtimer; }; struct { struct list_head tp_list; }; struct { long long unsigned int pwr_acc; long long unsigned int ptsc; }; struct { struct arch_hw_breakpoint info; struct rhlist_head bp_list; }; struct { u8 iommu_bank; u8 iommu_cntr; short unsigned int padding; long long unsigned int conf; long long unsigned int conf1; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hw_perf_event extends Union {
    public anon_member_of_anon_member_of_hw_perf_event anon0;

    public anon_member_of_anon_member_of_hw_perf_event anon1;

    public anon_member_of_anon_member_of_hw_perf_event anon2;

    public anon_member_of_anon_member_of_hw_perf_event anon3;

    public anon_member_of_anon_member_of_hw_perf_event anon4;

    public anon_member_of_anon_member_of_hw_perf_event anon5;

    public anon_member_of_anon_member_of_hw_perf_event anon6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int skip_read; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_perf_output_handle extends Struct {
    public @Unsigned long skip_read;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int flags; long long unsigned int aux_flags; struct { long long unsigned int skip_read; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_output_handle extends Union {
    public @Unsigned long flags;

    public @Unsigned long aux_flags;

    public anon_member_of_anon_member_of_perf_output_handle anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { const u8 *name; const int size; const int align; const unsigned int is_signed; unsigned int needs_test; const int filter_type; const int len; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_trace_event_fields extends Struct {
    public String name;

    public int size;

    public int align;

    public @Unsigned int is_signed;

    public @Unsigned int needs_test;

    public int filter_type;

    public int len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { const u8 *name; const int size; const int align; const unsigned int is_signed; unsigned int needs_test; const int filter_type; const int len; }; int (*define_fields)(struct trace_event_call*); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_trace_event_fields extends Union {
    public anon_member_of_anon_member_of_trace_event_fields anon0;

    public Ptr<?> define_fields;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const u8 *name; struct tracepoint *tp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_trace_event_call extends Union {
    public String name;

    public Ptr<tracepoint> tp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 *string; void *blob; struct filename *name; struct file *file; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fs_parameter extends Union {
    public String string;

    public Ptr<?> blob;

    public Ptr<filename> name;

    public Ptr<file> file;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { _Bool boolean; int int_32; unsigned int uint_32; long long unsigned int uint_64; struct { unsigned int val; } uid; struct { unsigned int val; } gid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fs_parse_result extends Union {
    public boolean _boolean;

    public int int_32;

    public @Unsigned int uint_32;

    public @Unsigned long uint_64;

    public kuid_t uid;

    public kgid_t gid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct sk_buff *next; struct sk_buff *prev; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_sk_buff_head extends Struct {
    public Ptr<sk_buff> next;

    public Ptr<sk_buff> prev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct sk_buff *next; struct sk_buff *prev; }; struct sk_buff_list list; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sk_buff_head extends Union {
    public anon_member_of_anon_member_of_sk_buff_head anon0;

    public sk_buff_list list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct net_device *dev; long unsigned int dev_scratch; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_sk_buff extends Union {
    public Ptr<net_device> dev;

    public @Unsigned long dev_scratch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct sk_buff *next; struct sk_buff *prev; union { struct net_device *dev; long unsigned int dev_scratch; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_sk_buff extends Struct {
    public Ptr<sk_buff> next;

    public Ptr<sk_buff> prev;

    @InlineUnion(2861)
    public Ptr<net_device> dev;

    @InlineUnion(2861)
    public @Unsigned long dev_scratch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct sk_buff *next; struct sk_buff *prev; union { struct net_device *dev; long unsigned int dev_scratch; }; }; struct rb_node rbnode; struct list_head list; struct llist_node ll_node; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sk_buff extends Union {
    public anon_member_of_anon_member_of_sk_buff anon0;

    public rb_node rbnode;

    public list_head list;

    public llist_node ll_node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int csum_start; short unsigned int csum_offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_sk_buff_and_headers_of_anon_member_of_sk_buff extends Struct {
    public @Unsigned short csum_start;

    public @Unsigned short csum_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int csum; struct { short unsigned int csum_start; short unsigned int csum_offset; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_sk_buff_and_headers_of_anon_member_of_sk_buff extends Union {
    public @Unsigned @OriginalName("__wsum") int csum;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_sk_buff_and_headers_of_anon_member_of_sk_buff anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 __pkt_type_offset[0]; u8 pkt_type; u8 ignore_df; u8 dst_pending_confirm; u8 ip_summed; u8 ooo_okay; u8 __mono_tc_offset[0]; u8 tstamp_type; u8 tc_at_ingress; u8 tc_skip_classify; u8 remcsum_offload; u8 csum_complete_sw; u8 csum_level; u8 inner_protocol_type; u8 l4_hash; u8 sw_hash; u8 wifi_acked_valid; u8 wifi_acked; u8 no_fcs; u8 encapsulation; u8 encap_hdr_csum; u8 csum_valid; u8 ndisc_nodetype; u8 ipvs_property; u8 nf_trace; u8 offload_fwd_mark; u8 offload_l3_fwd_mark; u8 redirected; u8 from_ingress; u8 nf_skip_egress; u8 decrypted; u8 slow_gro; u8 csum_not_inet; u8 unreadable; short unsigned int tc_index; short unsigned int alloc_cpu; union { unsigned int csum; struct { short unsigned int csum_start; short unsigned int csum_offset; }; }; unsigned int priority; int skb_iif; unsigned int hash; union { unsigned int vlan_all; struct { short unsigned int vlan_proto; short unsigned int vlan_tci; }; }; union { unsigned int napi_id; unsigned int sender_cpu; }; unsigned int secmark; union { unsigned int mark; unsigned int reserved_tailroom; }; union { short unsigned int inner_protocol; u8 inner_ipproto; }; short unsigned int inner_transport_header; short unsigned int inner_network_header; short unsigned int inner_mac_header; short unsigned int protocol; short unsigned int transport_header; short unsigned int network_header; short unsigned int mac_header; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_sk_buff_and_headers_of_anon_member_of_sk_buff extends Struct {
    public char @Size(0) [] __pkt_type_offset;

    public char pkt_type;

    public char ignore_df;

    public char dst_pending_confirm;

    public char ip_summed;

    public char ooo_okay;

    public char @Size(0) [] __mono_tc_offset;

    public char tstamp_type;

    public char tc_at_ingress;

    public char tc_skip_classify;

    public char remcsum_offload;

    public char csum_complete_sw;

    public char csum_level;

    public char inner_protocol_type;

    public char l4_hash;

    public char sw_hash;

    public char wifi_acked_valid;

    public char wifi_acked;

    public char no_fcs;

    public char encapsulation;

    public char encap_hdr_csum;

    public char csum_valid;

    public char ndisc_nodetype;

    public char ipvs_property;

    public char nf_trace;

    public char offload_fwd_mark;

    public char offload_l3_fwd_mark;

    public char redirected;

    public char from_ingress;

    public char nf_skip_egress;

    public char decrypted;

    public char slow_gro;

    public char csum_not_inet;

    public char unreadable;

    public @Unsigned short tc_index;

    public @Unsigned short alloc_cpu;

    @InlineUnion(2868)
    public @Unsigned @OriginalName("__wsum") int csum;

    @InlineUnion(2868)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_sk_buff_and_headers_of_anon_member_of_sk_buff anon36$1;

    public @Unsigned int priority;

    public int skb_iif;

    public @Unsigned int hash;

    @InlineUnion(2870)
    public @Unsigned int vlan_all;

    @InlineUnion(2870)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_sk_buff_and_headers_of_anon_member_of_sk_buff anon40$1;

    @InlineUnion(2871)
    public @Unsigned int napi_id;

    @InlineUnion(2871)
    public @Unsigned int sender_cpu;

    public @Unsigned int secmark;

    @InlineUnion(2872)
    public @Unsigned int mark;

    @InlineUnion(2872)
    public @Unsigned int reserved_tailroom;

    @InlineUnion(2873)
    public @Unsigned @OriginalName("__be16") short inner_protocol;

    @InlineUnion(2873)
    public char inner_ipproto;

    public @Unsigned short inner_transport_header;

    public @Unsigned short inner_network_header;

    public @Unsigned short inner_mac_header;

    public @Unsigned @OriginalName("__be16") short protocol;

    public @Unsigned short transport_header;

    public @Unsigned short network_header;

    public @Unsigned short mac_header;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_sa_data; u8 sa_data[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_sockaddr extends Struct {
    public lockdep_map_p __empty_sa_data;

    public char @Size(0) [] sa_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 sa_data_min[14]; struct { struct { } __empty_sa_data; u8 sa_data[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sockaddr extends Union {
    public char @Size(14) [] sa_data_min;

    public anon_member_of_anon_member_of_sockaddr anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *msg_control; void *msg_control_user; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_msghdr extends Union {
    public Ptr<?> msg_control;

    public Ptr<?> msg_control_user;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct tty_buffer *next; struct llist_node free; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tty_buffer extends Union {
    public Ptr<tty_buffer> next;

    public llist_node free;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct __kfifo kfifo; u8 *type; const u8 *const_type; u8 (*rectype)[0]; u8 *ptr; const u8 *ptr_const; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_xmit_fifo_of_tty_port extends Union {
    public __kfifo kfifo;

    public Ptr<java.lang.Character> type;

    public Ptr<java.lang.Character> const_type;

    public Ptr<char @Size(0) []> rectype;

    public Ptr<java.lang.Character> ptr;

    public Ptr<java.lang.Character> ptr_const;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *kernel; void *user; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sockptr_t extends Union {
    public Ptr<?> kernel;

    public Ptr<?> user;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long int hwtstamp; void *netdev_data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_skb_shared_hwtstamps extends Union {
    public @OriginalName("ktime_t") long hwtstamp;

    public Ptr<?> netdev_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 ctx[48]; long int args[6]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_netlink_callback extends Union {
    public char @Size(48) [] ctx;

    public long @Size(6) [] args;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int rx_packets; struct { long long int counter; } __rx_packets; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_net_device_stats extends Union {
    public @Unsigned long rx_packets;

    public @OriginalName("atomic_long_t") atomic64_t __rx_packets;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int id; short unsigned int proto; u8 h_dest[6]; } encap; struct { enum vlan_mode_of_bridge_of_anon_member_of_net_device_path vlan_mode; short unsigned int vlan_id; short unsigned int vlan_proto; } bridge; struct { int port; short unsigned int proto; } dsa; struct { u8 wdma_idx; u8 queue; short unsigned int wcid; u8 bss; u8 amsdu; } mtk_wdma; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_net_device_path extends Union {
    public encap_of_anon_member_of_net_device_path encap;

    public bridge_of_anon_member_of_net_device_path bridge;

    public dsa_of_anon_member_of_net_device_path dsa;

    public mtk_wdma_of_anon_member_of_net_device_path mtk_wdma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int flags; struct bpf_prog *prog; struct netlink_ext_ack *extack; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_netdev_bpf extends Struct {
    public @Unsigned int flags;

    public Ptr<bpf_prog> prog;

    public Ptr<netlink_ext_ack> extack;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int flags; struct bpf_prog *prog; struct netlink_ext_ack *extack; }; struct { struct bpf_offloaded_map *offmap; }; struct { struct xsk_buff_pool *pool; short unsigned int queue_id; } xsk; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_netdev_bpf extends Union {
    public anon_member_of_anon_member_of_netdev_bpf anon0;

    public anon_member_of_anon_member_of_netdev_bpf anon1;

    public xsk_of_anon_member_of_netdev_bpf xsk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int priv_flags; long unsigned int lltx; long unsigned int netmem_tx; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_net_device_and_priv_flags_fast_of_anon_member_of_net_device extends Struct {
    public @Unsigned long priv_flags;

    public @Unsigned long lltx;

    public @Unsigned long netmem_tx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long unsigned int priv_flags; long unsigned int lltx; long unsigned int netmem_tx; }; struct { long unsigned int priv_flags; long unsigned int lltx; long unsigned int netmem_tx; } priv_flags_fast; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_net_device extends Union {
    public anon_member_of_anon_member_of_net_device_and_priv_flags_fast_of_anon_member_of_net_device anon0;

    public anon_member_of_anon_member_of_net_device_and_priv_flags_fast_of_anon_member_of_net_device priv_flags_fast;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short int min; short int max; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_nla_policy extends Struct {
    public short min;

    public short max;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int strict_start_type; const unsigned int bitfield32_valid; const unsigned int mask; const u8 *reject_message; const struct nla_policy *nested_policy; const struct netlink_range_validation *range; const struct netlink_range_validation_signed *range_signed; struct { short int min; short int max; }; int (*validate)(const struct nlattr*, struct netlink_ext_ack*); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nla_policy extends Union {
    public @Unsigned short strict_start_type;

    public @Unsigned int bitfield32_valid;

    public @Unsigned int mask;

    public String reject_message;

    public Ptr<nla_policy> nested_policy;

    public Ptr<netlink_range_validation> range;

    public Ptr<netlink_range_validation_signed> range_signed;

    public anon_member_of_anon_member_of_nla_policy anon7;

    public Ptr<?> validate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head free_node; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pneigh_entry extends Union {
    public list_head free_node;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct net_device *dev; struct net_device *dev_rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dst_entry extends Union {
    public Ptr<net_device> dev;

    public Ptr<net_device> dev_rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int skc_daddr; unsigned int skc_rcv_saddr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_sock_common extends Struct {
    public @Unsigned @OriginalName("__be32") int skc_daddr;

    public @Unsigned @OriginalName("__be32") int skc_rcv_saddr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int skc_addrpair; struct { unsigned int skc_daddr; unsigned int skc_rcv_saddr; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sock_common extends Union {
    public @Unsigned @OriginalName("__addrpair") long skc_addrpair;

    public anon_member_of_anon_member_of_sock_common anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct socket_wq *sk_wq; struct socket_wq *sk_wq_raw; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sock extends Union {
    public Ptr<socket_wq> sk_wq;

    public Ptr<socket_wq> sk_wq_raw;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 sk_scm_credentials; u8 sk_scm_security; u8 sk_scm_pidfd; u8 sk_scm_rights; u8 sk_scm_unused; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_sock extends Struct {
    public char sk_scm_credentials;

    public char sk_scm_security;

    public char sk_scm_pidfd;

    public char sk_scm_rights;

    public char sk_scm_unused;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int val; } e_uid; struct { unsigned int val; } e_gid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_posix_acl_entry extends Union {
    public kuid_t e_uid;

    public kgid_t e_gid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { refcount_struct a_refcount; unsigned int a_count; struct callback_head a_rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_posix_acl extends Struct {
    public @OriginalName("refcount_t") refcount_struct a_refcount;

    public @Unsigned int a_count;

    public callback_head a_rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { refcount_struct a_refcount; unsigned int a_count; struct callback_head a_rcu; }; struct posix_acl_hdr hdr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_posix_acl extends Union {
    public anon_member_of_anon_member_of_posix_acl anon0;

    public posix_acl_hdr hdr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int intel_native_model_id; unsigned int intel_type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_cpuinfo_topology extends Struct {
    public @Unsigned int intel_native_model_id;

    public @Unsigned int intel_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int cpu_type; struct { unsigned int intel_native_model_id; unsigned int intel_type; }; struct { unsigned int amd_num_processors; unsigned int amd_power_eff_ranking; unsigned int amd_native_model_id; unsigned int amd_type; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_cpuinfo_topology extends Union {
    public @Unsigned int cpu_type;

    public anon_member_of_anon_member_of_cpuinfo_topology anon1;

    public anon_member_of_anon_member_of_cpuinfo_topology anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 x86_model; u8 x86; u8 x86_vendor; u8 x86_reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_cpuinfo_x86 extends Struct {
    public char x86_model;

    public char x86;

    public char x86_vendor;

    public char x86_reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 x86_model; u8 x86; u8 x86_vendor; u8 x86_reserved; }; unsigned int x86_vfm; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_cpuinfo_x86 extends Union {
    public anon_member_of_anon_member_of_cpuinfo_x86 anon0;

    public @Unsigned int x86_vfm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int value; u8 bytes[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_insn_field extends Union {
    public @OriginalName("insn_value_t") int value;

    public @OriginalName("insn_byte_t") char @Size(4) [] bytes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct insn_field immediate; struct insn_field moffset1; struct insn_field immediate1; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_insn extends Union {
    public insn_field immediate;

    public insn_field moffset1;

    public insn_field immediate1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; long unsigned int (*get_time)(struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*, struct { unsigned int resolution; unsigned int accuracy; u8 sets_to_zero; }*); long unsigned int (*set_time)(struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*get_wakeup_time)(u8*, u8*, struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*set_wakeup_time)(u8, struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*set_virtual_address_map)(long unsigned int, long unsigned int, unsigned int, struct { unsigned int type; unsigned int pad; long long unsigned int phys_addr; long long unsigned int virt_addr; long long unsigned int num_pages; long long unsigned int attribute; }*); void *convert_pointer; long unsigned int (*get_variable)(short unsigned int*, struct { u8 b[16]; }*, unsigned int*, long unsigned int*, void*); long unsigned int (*get_next_variable)(long unsigned int*, short unsigned int*, struct { u8 b[16]; }*); long unsigned int (*set_variable)(short unsigned int*, struct { u8 b[16]; }*, unsigned int, long unsigned int, void*); long unsigned int (*get_next_high_mono_count)(unsigned int*); void (*reset_system)(int, long unsigned int, long unsigned int, short unsigned int*); long unsigned int (*update_capsule)(struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; }**, long unsigned int, long unsigned int); long unsigned int (*query_capsule_caps)(struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; }**, long unsigned int, long long unsigned int*, int*); long unsigned int (*query_variable_info)(unsigned int, long long unsigned int*, long long unsigned int*, long long unsigned int*); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_efi_runtime_services_t extends Struct {
    public efi_table_hdr_t hdr;

    public Ptr<?> get_time;

    public Ptr<?> set_time;

    public Ptr<?> get_wakeup_time;

    public Ptr<?> set_wakeup_time;

    public Ptr<?> set_virtual_address_map;

    public Ptr<?> convert_pointer;

    public Ptr<?> get_variable;

    public Ptr<?> get_next_variable;

    public Ptr<?> set_variable;

    public Ptr<?> get_next_high_mono_count;

    public Ptr<?> reset_system;

    public Ptr<?> update_capsule;

    public Ptr<?> query_capsule_caps;

    public Ptr<?> query_variable_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { _Bool exit_rcu; _Bool lockdep; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_irqentry_state_and_anon_member_of_irqentry_state_t extends Union {
    public boolean exit_rcu;

    public boolean lockdep;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int cpuid; unsigned int flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_alt_instr extends Struct {
    public @Unsigned int cpuid;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int cpuid; unsigned int flags; }; unsigned int ft_flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_alt_instr extends Union {
    public anon_member_of_anon_member_of_alt_instr anon0;

    public @Unsigned int ft_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int cap_bit0; long long unsigned int cap_bit0_is_deprecated; long long unsigned int cap_user_rdpmc; long long unsigned int cap_user_time; long long unsigned int cap_user_time_zero; long long unsigned int cap_user_time_short; long long unsigned int cap_____res; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_perf_event_mmap_page extends Struct {
    public @Unsigned long cap_bit0;

    public @Unsigned long cap_bit0_is_deprecated;

    public @Unsigned long cap_user_rdpmc;

    public @Unsigned long cap_user_time;

    public @Unsigned long cap_user_time_zero;

    public @Unsigned long cap_user_time_short;

    public @Unsigned long cap_____res;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int capabilities; struct { long long unsigned int cap_bit0; long long unsigned int cap_bit0_is_deprecated; long long unsigned int cap_user_rdpmc; long long unsigned int cap_user_time; long long unsigned int cap_user_time_zero; long long unsigned int cap_user_time_short; long long unsigned int cap_____res; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_event_mmap_page extends Union {
    public @Unsigned long capabilities;

    public anon_member_of_anon_member_of_perf_event_mmap_page anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int idxmsk[1]; long long unsigned int idxmsk64; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_event_constraint extends Union {
    public @Unsigned long @Size(1) [] idxmsk;

    public @Unsigned long idxmsk64;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int has_exclusive[2]; unsigned int exclusive_present; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_intel_excl_cntrs extends Union {
    public @Unsigned short @Size(2) [] has_exclusive;

    public @Unsigned int exclusive_present;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct er_account *lbr_sel; struct er_account *lbr_ctl; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_cpu_hw_events extends Union {
    public Ptr<er_account> lbr_sel;

    public Ptr<er_account> lbr_ctl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int lbr_format; long long unsigned int pebs_trap; long long unsigned int pebs_arch_reg; long long unsigned int pebs_format; long long unsigned int smm_freeze; long long unsigned int full_width_write; long long unsigned int pebs_baseline; long long unsigned int perf_metrics; long long unsigned int pebs_output_pt_available; long long unsigned int pebs_timing_info; long long unsigned int anythread_deprecated; long long unsigned int rdpmc_metrics_clear; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_capabilities extends Struct {
    public @Unsigned long lbr_format;

    public @Unsigned long pebs_trap;

    public @Unsigned long pebs_arch_reg;

    public @Unsigned long pebs_format;

    public @Unsigned long smm_freeze;

    public @Unsigned long full_width_write;

    public @Unsigned long pebs_baseline;

    public @Unsigned long perf_metrics;

    public @Unsigned long pebs_output_pt_available;

    public @Unsigned long pebs_timing_info;

    public @Unsigned long anythread_deprecated;

    public @Unsigned long rdpmc_metrics_clear;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int cntr_mask64; long unsigned int cntr_mask[1]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_x86_hybrid_pmu_and_anon_member_of_x86_pmu extends Union {
    public @Unsigned long cntr_mask64;

    public @Unsigned long @Size(1) [] cntr_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int events_maskl; long unsigned int events_mask[1]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_x86_pmu extends Union {
    public @Unsigned long events_maskl;

    public @Unsigned long @Size(1) [] events_mask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int rsvd0; long long unsigned int brsmen; long long unsigned int rsvd4_3; long long unsigned int vb; long long unsigned int rsvd2; long long unsigned int msroff; long long unsigned int rsvd3; long long unsigned int pmc; long long unsigned int rsvd4; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_amd_debug_extn_cfg extends Struct {
    public @Unsigned long rsvd0;

    public @Unsigned long brsmen;

    public @Unsigned long rsvd4_3;

    public @Unsigned long vb;

    public @Unsigned long rsvd2;

    public @Unsigned long msroff;

    public @Unsigned long rsvd3;

    public @Unsigned long pmc;

    public @Unsigned long rsvd4;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct pci_sriov *sriov; struct pci_dev *physfn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pci_dev extends Union {
    public Ptr<pci_sriov> sriov;

    public Ptr<pci_dev> physfn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int fetch_maxcnt; long long unsigned int fetch_cnt; long long unsigned int fetch_lat; long long unsigned int fetch_en; long long unsigned int fetch_val; long long unsigned int fetch_comp; long long unsigned int ic_miss; long long unsigned int phy_addr_valid; long long unsigned int l1tlb_pgsz; long long unsigned int l1tlb_miss; long long unsigned int l2tlb_miss; long long unsigned int rand_en; long long unsigned int fetch_l2_miss; long long unsigned int l3_miss_only; long long unsigned int fetch_oc_miss; long long unsigned int fetch_l3_miss; long long unsigned int reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ibs_fetch_ctl extends Struct {
    public @Unsigned long fetch_maxcnt;

    public @Unsigned long fetch_cnt;

    public @Unsigned long fetch_lat;

    public @Unsigned long fetch_en;

    public @Unsigned long fetch_val;

    public @Unsigned long fetch_comp;

    public @Unsigned long ic_miss;

    public @Unsigned long phy_addr_valid;

    public @Unsigned long l1tlb_pgsz;

    public @Unsigned long l1tlb_miss;

    public @Unsigned long l2tlb_miss;

    public @Unsigned long rand_en;

    public @Unsigned long fetch_l2_miss;

    public @Unsigned long l3_miss_only;

    public @Unsigned long fetch_oc_miss;

    public @Unsigned long fetch_l3_miss;

    public @Unsigned long reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int opmaxcnt; long long unsigned int l3_miss_only; long long unsigned int op_en; long long unsigned int op_val; long long unsigned int cnt_ctl; long long unsigned int opmaxcnt_ext; long long unsigned int reserved0; long long unsigned int opcurcnt; long long unsigned int ldlat_thrsh; long long unsigned int ldlat_en; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ibs_op_ctl extends Struct {
    public @Unsigned long opmaxcnt;

    public @Unsigned long l3_miss_only;

    public @Unsigned long op_en;

    public @Unsigned long op_val;

    public @Unsigned long cnt_ctl;

    public @Unsigned long opmaxcnt_ext;

    public @Unsigned long reserved0;

    public @Unsigned long opcurcnt;

    public @Unsigned long ldlat_thrsh;

    public @Unsigned long ldlat_en;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int comp_to_ret_ctr; long long unsigned int tag_to_ret_ctr; long long unsigned int reserved1; long long unsigned int op_return; long long unsigned int op_brn_taken; long long unsigned int op_brn_misp; long long unsigned int op_brn_ret; long long unsigned int op_rip_invalid; long long unsigned int op_brn_fuse; long long unsigned int op_microcode; long long unsigned int reserved2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ibs_op_data extends Struct {
    public @Unsigned long comp_to_ret_ctr;

    public @Unsigned long tag_to_ret_ctr;

    public @Unsigned long reserved1;

    public @Unsigned long op_return;

    public @Unsigned long op_brn_taken;

    public @Unsigned long op_brn_misp;

    public @Unsigned long op_brn_ret;

    public @Unsigned long op_rip_invalid;

    public @Unsigned long op_brn_fuse;

    public @Unsigned long op_microcode;

    public @Unsigned long reserved2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int data_src_lo; long long unsigned int reserved0; long long unsigned int rmt_node; long long unsigned int cache_hit_st; long long unsigned int data_src_hi; long long unsigned int reserved1; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ibs_op_data2 extends Struct {
    public @Unsigned long data_src_lo;

    public @Unsigned long reserved0;

    public @Unsigned long rmt_node;

    public @Unsigned long cache_hit_st;

    public @Unsigned long data_src_hi;

    public @Unsigned long reserved1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int ld_op; long long unsigned int st_op; long long unsigned int dc_l1tlb_miss; long long unsigned int dc_l2tlb_miss; long long unsigned int dc_l1tlb_hit_2m; long long unsigned int dc_l1tlb_hit_1g; long long unsigned int dc_l2tlb_hit_2m; long long unsigned int dc_miss; long long unsigned int dc_mis_acc; long long unsigned int reserved; long long unsigned int dc_wc_mem_acc; long long unsigned int dc_uc_mem_acc; long long unsigned int dc_locked_op; long long unsigned int dc_miss_no_mab_alloc; long long unsigned int dc_lin_addr_valid; long long unsigned int dc_phy_addr_valid; long long unsigned int dc_l2_tlb_hit_1g; long long unsigned int l2_miss; long long unsigned int sw_pf; long long unsigned int op_mem_width; long long unsigned int op_dc_miss_open_mem_reqs; long long unsigned int dc_miss_lat; long long unsigned int tlb_refill_lat; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ibs_op_data3 extends Struct {
    public @Unsigned long ld_op;

    public @Unsigned long st_op;

    public @Unsigned long dc_l1tlb_miss;

    public @Unsigned long dc_l2tlb_miss;

    public @Unsigned long dc_l1tlb_hit_2m;

    public @Unsigned long dc_l1tlb_hit_1g;

    public @Unsigned long dc_l2tlb_hit_2m;

    public @Unsigned long dc_miss;

    public @Unsigned long dc_mis_acc;

    public @Unsigned long reserved;

    public @Unsigned long dc_wc_mem_acc;

    public @Unsigned long dc_uc_mem_acc;

    public @Unsigned long dc_locked_op;

    public @Unsigned long dc_miss_no_mab_alloc;

    public @Unsigned long dc_lin_addr_valid;

    public @Unsigned long dc_phy_addr_valid;

    public @Unsigned long dc_l2_tlb_hit_1g;

    public @Unsigned long l2_miss;

    public @Unsigned long sw_pf;

    public @Unsigned long op_mem_width;

    public @Unsigned long op_dc_miss_open_mem_reqs;

    public @Unsigned long dc_miss_lat;

    public @Unsigned long tlb_refill_lat;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int data[0]; unsigned int caps; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_ibs_data extends Union {
    public @Unsigned int @Size(0) [] data;

    public @Unsigned int caps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int rip; long long unsigned int rdp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_fxregs_state extends Struct {
    public @Unsigned long rip;

    public @Unsigned long rdp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int rip; long long unsigned int rdp; }; struct { unsigned int fip; unsigned int fcs; unsigned int foo; unsigned int fos; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fxregs_state extends Union {
    public anon_member_of_anon_member_of_fxregs_state anon0;

    public anon_member_of_anon_member_of_fxregs_state anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ioapic_alloc_info ioapic; struct uv_alloc_info uv; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_irq_alloc_info_and_anon_member_of_msi_alloc_info_t extends Union {
    public ioapic_alloc_info ioapic;

    public uv_alloc_info uv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int vector; unsigned int delivery_mode; unsigned int dest_mode_logical; unsigned int reserved; unsigned int active_low; unsigned int is_level; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_arch_msi_msg_data_t_and_anon_member_of_x86_msi_data extends Struct {
    public @Unsigned int vector;

    public @Unsigned int delivery_mode;

    public @Unsigned int dest_mode_logical;

    public @Unsigned int reserved;

    public @Unsigned int active_low;

    public @Unsigned int is_level;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int vector; unsigned int delivery_mode; unsigned int dest_mode_logical; unsigned int reserved; unsigned int active_low; unsigned int is_level; }; unsigned int dmar_subhandle; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_arch_msi_msg_data_t_and_anon_member_of_x86_msi_data extends Union {
    public anon_member_of_anon_member_of_arch_msi_msg_data_t_and_anon_member_of_x86_msi_data anon0;

    public @Unsigned int dmar_subhandle;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int reserved_0; unsigned int dest_mode_logical; unsigned int redirect_hint; unsigned int reserved_1; unsigned int virt_destid_8_14; unsigned int destid_0_7; unsigned int base_address; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_arch_msi_msg_addr_lo_t_and_anon_member_of_x86_msi_addr_lo extends Struct {
    public @Unsigned int reserved_0;

    public @Unsigned int dest_mode_logical;

    public @Unsigned int redirect_hint;

    public @Unsigned int reserved_1;

    public @Unsigned int virt_destid_8_14;

    public @Unsigned int destid_0_7;

    public @Unsigned int base_address;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int reserved_0; unsigned int dest_mode_logical; unsigned int redirect_hint; unsigned int reserved_1; unsigned int virt_destid_8_14; unsigned int destid_0_7; unsigned int base_address; }; struct { unsigned int dmar_reserved_0; unsigned int dmar_index_15; unsigned int dmar_subhandle_valid; unsigned int dmar_format; unsigned int dmar_index_0_14; unsigned int dmar_base_address; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_arch_msi_msg_addr_lo_t_and_anon_member_of_x86_msi_addr_lo extends Union {
    public anon_member_of_anon_member_of_arch_msi_msg_addr_lo_t_and_anon_member_of_x86_msi_addr_lo anon0;

    public anon_member_of_anon_member_of_arch_msi_msg_addr_lo_t_and_anon_member_of_x86_msi_addr_lo anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int address_lo; x86_msi_addr_lo arch_addr_lo; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_msi_msg extends Union {
    public @Unsigned int address_lo;

    public @OriginalName("arch_msi_msg_addr_lo_t") x86_msi_addr_lo arch_addr_lo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int msi_mask; unsigned int msix_ctrl; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pci_msi_desc extends Union {
    public @Unsigned int msi_mask;

    public @Unsigned int msix_ctrl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct pci_msi_desc pci; struct msi_desc_data data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_msi_desc extends Union {
    public pci_msi_desc pci;

    public msi_desc_data data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_vmx; struct kvm_vmx_nested_state_data vmx[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_data_of_kvm_nested_state extends Struct {
    public lockdep_map_p __empty_vmx;

    public kvm_vmx_nested_state_data @Size(0) [] vmx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hypercall_of_anon_member_of_kvm_run extends Union {
    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 insn_size; u8 insn_bytes[15]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_emulation_failure_of_anon_member_of_kvm_run extends Struct {
    public char insn_size;

    public char @Size(15) [] insn_bytes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 insn_size; u8 insn_bytes[15]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_emulation_failure_of_anon_member_of_kvm_run extends Union {
    public anon_member_of_anon_member_of_emulation_failure_of_anon_member_of_kvm_run anon0;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int data[16]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_system_event_of_anon_member_of_kvm_run extends Union {
    public @Unsigned long @Size(16) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int ret; long long unsigned int data[5]; } unknown; struct { long long unsigned int ret; long long unsigned int gpa; long long unsigned int size; } get_quote; struct { long long unsigned int ret; long long unsigned int leaf; long long unsigned int r11; long long unsigned int r12; long long unsigned int r13; long long unsigned int r14; } get_tdvmcall_info; struct { long long unsigned int ret; long long unsigned int vector; } setup_event_notify; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tdx_of_anon_member_of_kvm_run extends Union {
    public unknown_of_anon_member_of_tdx_of_anon_member_of_kvm_run unknown;

    public get_quote_of_anon_member_of_tdx_of_anon_member_of_kvm_run get_quote;

    public get_tdvmcall_info_of_anon_member_of_tdx_of_anon_member_of_kvm_run get_tdvmcall_info;

    public setup_event_notify_of_anon_member_of_tdx_of_anon_member_of_kvm_run setup_event_notify;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int hardware_exit_reason; } hw; struct { long long unsigned int hardware_entry_failure_reason; unsigned int cpu; } fail_entry; struct { unsigned int exception; unsigned int error_code; } ex; struct { u8 direction; u8 size; short unsigned int port; unsigned int count; long long unsigned int data_offset; } io; struct { struct kvm_debug_exit_arch arch; } debug; struct { long long unsigned int phys_addr; u8 data[8]; unsigned int len; u8 is_write; } mmio; struct { long long unsigned int phys_addr; u8 data[8]; unsigned int len; u8 is_write; } iocsr_io; struct { long long unsigned int nr; long long unsigned int args[6]; long long unsigned int ret; union { long long unsigned int flags; }; } hypercall; struct { long long unsigned int rip; unsigned int is_write; unsigned int pad; } tpr_access; struct { u8 icptcode; short unsigned int ipa; unsigned int ipb; } s390_sieic; long long unsigned int s390_reset_flags; struct { long long unsigned int trans_exc_code; unsigned int pgm_code; } s390_ucontrol; struct { unsigned int dcrn; unsigned int data; u8 is_write; } dcr; struct { unsigned int suberror; unsigned int ndata; long long unsigned int data[16]; } internal; struct { unsigned int suberror; unsigned int ndata; long long unsigned int flags; union { struct { u8 insn_size; u8 insn_bytes[15]; }; }; } emulation_failure; struct { long long unsigned int gprs[32]; } osi; struct { long long unsigned int nr; long long unsigned int ret; long long unsigned int args[9]; } papr_hcall; struct { short unsigned int subchannel_id; short unsigned int subchannel_nr; unsigned int io_int_parm; unsigned int io_int_word; unsigned int ipb; u8 dequeued; } s390_tsch; struct { unsigned int epr; } epr; struct { unsigned int type; unsigned int ndata; union { long long unsigned int data[16]; }; } system_event; struct { long long unsigned int addr; u8 ar; u8 reserved; u8 fc; u8 sel1; short unsigned int sel2; } s390_stsi; struct { u8 vector; } eoi; struct kvm_hyperv_exit hyperv; struct { long long unsigned int esr_iss; long long unsigned int fault_ipa; } arm_nisv; struct { u8 error; u8 pad[7]; unsigned int reason; unsigned int index; long long unsigned int data; } msr; struct kvm_xen_exit xen; struct { long unsigned int extension_id; long unsigned int function_id; long unsigned int args[6]; long unsigned int ret[2]; } riscv_sbi; struct { long unsigned int csr_num; long unsigned int new_value; long unsigned int write_mask; long unsigned int ret_value; } riscv_csr; struct { unsigned int flags; } notify; struct { long long unsigned int flags; long long unsigned int gpa; long long unsigned int size; } memory_fault; struct { long long unsigned int flags; long long unsigned int nr; union { struct { long long unsigned int ret; long long unsigned int data[5]; } unknown; struct { long long unsigned int ret; long long unsigned int gpa; long long unsigned int size; } get_quote; struct { long long unsigned int ret; long long unsigned int leaf; long long unsigned int r11; long long unsigned int r12; long long unsigned int r13; long long unsigned int r14; } get_tdvmcall_info; struct { long long unsigned int ret; long long unsigned int vector; } setup_event_notify; }; } tdx; u8 padding[256]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kvm_run extends Union {
    public hw_of_anon_member_of_kvm_run hw;

    public fail_entry_of_anon_member_of_kvm_run fail_entry;

    public ex_of_anon_member_of_kvm_run ex;

    public io_of_anon_member_of_kvm_run io;

    public debug_of_anon_member_of_kvm_run debug;

    public iocsr_io_of_anon_member_of_kvm_run_and_mmio_of_anon_member_of_kvm_run mmio;

    public iocsr_io_of_anon_member_of_kvm_run_and_mmio_of_anon_member_of_kvm_run iocsr_io;

    public hypercall_of_anon_member_of_kvm_run hypercall;

    public tpr_access_of_anon_member_of_kvm_run tpr_access;

    public s390_sieic_of_anon_member_of_kvm_run s390_sieic;

    public @Unsigned long s390_reset_flags;

    public s390_ucontrol_of_anon_member_of_kvm_run s390_ucontrol;

    public dcr_of_anon_member_of_kvm_run dcr;

    public internal_of_anon_member_of_kvm_run internal;

    public emulation_failure_of_anon_member_of_kvm_run emulation_failure;

    public osi_of_anon_member_of_kvm_run osi;

    public papr_hcall_of_anon_member_of_kvm_run papr_hcall;

    public s390_tsch_of_anon_member_of_kvm_run s390_tsch;

    public epr_of_anon_member_of_kvm_run epr;

    public system_event_of_anon_member_of_kvm_run system_event;

    public s390_stsi_of_anon_member_of_kvm_run s390_stsi;

    public eoi_of_anon_member_of_kvm_run eoi;

    public kvm_hyperv_exit hyperv;

    public arm_nisv_of_anon_member_of_kvm_run arm_nisv;

    public msr_of_anon_member_of_kvm_run msr;

    public kvm_xen_exit xen;

    public riscv_sbi_of_anon_member_of_kvm_run riscv_sbi;

    public riscv_csr_of_anon_member_of_kvm_run riscv_csr;

    public notify_of_anon_member_of_kvm_run_and_v2_of_jailhouse_setup_data notify;

    public memory_fault_of_anon_member_of_kvm_run memory_fault;

    public tdx_of_anon_member_of_kvm_run tdx;

    public char @Size(256) [] padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int pad; unsigned int pio; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kvm_coalesced_mmio extends Union {
    public @Unsigned int pad;

    public @Unsigned int pio;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int enable; long long unsigned int periodic; long long unsigned int lazy; long long unsigned int auto_enable; long long unsigned int apic_vector; long long unsigned int direct_mode; long long unsigned int reserved_z0; long long unsigned int sintx; long long unsigned int reserved_z1; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_stimer_config extends Struct {
    public @Unsigned long enable;

    public @Unsigned long periodic;

    public @Unsigned long lazy;

    public @Unsigned long auto_enable;

    public @Unsigned long apic_vector;

    public @Unsigned long direct_mode;

    public @Unsigned long reserved_z0;

    public @Unsigned long sintx;

    public @Unsigned long reserved_z1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 msg_pending; u8 reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_message_flags extends Struct {
    public char msg_pending;

    public char reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int sender; union hv_port_id port; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_message_header extends Union {
    public @Unsigned long sender;

    public hv_port_id port;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int level; unsigned int has_4_byte_gpte; unsigned int quadrant; unsigned int direct; unsigned int access; unsigned int invalid; unsigned int efer_nx; unsigned int cr0_wp; unsigned int smep_andnot_wp; unsigned int smap_andnot_wp; unsigned int ad_disabled; unsigned int guest_mode; unsigned int passthrough; unsigned int is_mirror; unsigned int smm; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kvm_mmu_page_role extends Struct {
    public @Unsigned int level;

    public @Unsigned int has_4_byte_gpte;

    public @Unsigned int quadrant;

    public @Unsigned int direct;

    public @Unsigned int access;

    public @Unsigned int invalid;

    public @Unsigned int efer_nx;

    public @Unsigned int cr0_wp;

    public @Unsigned int smep_andnot_wp;

    public @Unsigned int smap_andnot_wp;

    public @Unsigned int ad_disabled;

    public @Unsigned int guest_mode;

    public @Unsigned int passthrough;

    public @Unsigned int is_mirror;

    public @Unsigned int smm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int valid; unsigned int execonly; unsigned int cr4_pse; unsigned int cr4_pke; unsigned int cr4_smap; unsigned int cr4_smep; unsigned int cr4_la57; unsigned int efer_lma; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kvm_mmu_extended_role extends Struct {
    public @Unsigned int valid;

    public @Unsigned int execonly;

    public @Unsigned int cr4_pse;

    public @Unsigned int cr4_pke;

    public @Unsigned int cr4_smap;

    public @Unsigned int cr4_smep;

    public @Unsigned int cr4_la57;

    public @Unsigned int efer_lma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { union kvm_mmu_page_role base; union kvm_mmu_extended_role ext; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kvm_cpu_role extends Struct {
    public kvm_mmu_page_role base;

    public kvm_mmu_extended_role ext;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int reprogram_pmi[1]; struct { long long int counter; } __reprogram_pmi; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kvm_pmu extends Union {
    public @Unsigned long @Size(1) [] reprogram_pmi;

    public atomic64_t __reprogram_pmi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct __kfifo kfifo; long long unsigned int *type; const long long unsigned int *const_type; u8 (*rectype)[0]; long long unsigned int *ptr; const long long unsigned int *ptr_const; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_entries_of_kvm_vcpu_hv_tlb_flush_fifo extends Union {
    public __kfifo kfifo;

    public Ptr<java.lang. @Unsigned Long> type;

    public Ptr<java.lang. @Unsigned Long> const_type;

    public Ptr<char @Size(0) []> rectype;

    public Ptr<java.lang. @Unsigned Long> ptr;

    public Ptr<java.lang. @Unsigned Long> ptr_const;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { kvm_lapic* xapic_flat_map[8]; kvm_lapic* xapic_cluster_map[64]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kvm_apic_map extends Union {
    public @OriginalName("kvm_lapic") Ptr<?> @Size(8) [] xapic_flat_map;

    public @OriginalName("kvm_lapic") Ptr<?> @Size(64) [] xapic_cluster_map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { long long int counter; } pages_4k; struct { long long int counter; } pages_2m; struct { long long int counter; } pages_1g; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_kvm_vm_stat extends Struct {
    public atomic64_t pages_4k;

    public atomic64_t pages_2m;

    public atomic64_t pages_1g;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { long long int counter; } pages_4k; struct { long long int counter; } pages_2m; struct { long long int counter; } pages_1g; }; struct { long long int counter; } pages[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kvm_vm_stat extends Union {
    public anon_member_of_anon_member_of_kvm_vm_stat anon0;

    public atomic64_t @Size(3) [] pages;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int instr_latency; long long unsigned int pad2; long long unsigned int cache_latency; long long unsigned int pad3; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_pebs_meminfo extends Struct {
    public @Unsigned long instr_latency;

    public @Unsigned long pad2;

    public @Unsigned long cache_latency;

    public @Unsigned long pad3;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int mem_latency; struct { long long unsigned int instr_latency; long long unsigned int pad2; long long unsigned int cache_latency; long long unsigned int pad3; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pebs_meminfo extends Union {
    public @Unsigned long mem_latency;

    public anon_member_of_anon_member_of_pebs_meminfo anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int ld_dse; unsigned int ld_stlb_miss; unsigned int ld_locked; unsigned int ld_data_blk; unsigned int ld_addr_blk; unsigned int ld_reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_intel_x86_pebs_dse extends Struct {
    public @Unsigned int ld_dse;

    public @Unsigned int ld_stlb_miss;

    public @Unsigned int ld_locked;

    public @Unsigned int ld_data_blk;

    public @Unsigned int ld_addr_blk;

    public @Unsigned int ld_reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int cycles_last_block; unsigned int hle_abort; unsigned int rtm_abort; unsigned int instruction_abort; unsigned int non_instruction_abort; unsigned int retry; unsigned int data_conflict; unsigned int capacity_writes; unsigned int capacity_reads; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hsw_tsx_tuning extends Struct {
    public @Unsigned int cycles_last_block;

    public @Unsigned int hle_abort;

    public @Unsigned int rtm_abort;

    public @Unsigned int instruction_abort;

    public @Unsigned int non_instruction_abort;

    public @Unsigned int retry;

    public @Unsigned int data_conflict;

    public @Unsigned int capacity_writes;

    public @Unsigned int capacity_reads;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct fxregs_state i387; struct xstate_header header; struct arch_lbr_state lbr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_x86_perf_task_context_arch_lbr_xsave extends Struct {
    public fxregs_state i387;

    public xstate_header header;

    public arch_lbr_state lbr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct xregs_state xsave; struct { struct fxregs_state i387; struct xstate_header header; struct arch_lbr_state lbr; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_x86_perf_task_context_arch_lbr_xsave extends Union {
    public xregs_state xsave;

    public anon_member_of_anon_member_of_x86_perf_task_context_arch_lbr_xsave anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int msr_offset; unsigned int mmio_offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_intel_uncore_type extends Union {
    public @Unsigned int msr_offset;

    public @Unsigned int mmio_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *untyped; struct uncore_iio_topology *iio; struct uncore_upi_topology *upi; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_intel_uncore_topology extends Union {
    public Ptr<?> untyped;

    public Ptr<uncore_iio_topology> iio;

    public Ptr<uncore_upi_topology> upi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int type; long long unsigned int stride; long long unsigned int max_units; long long unsigned int __reserved_1; long long unsigned int access_type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_uncore_global_discovery extends Struct {
    public @Unsigned long type;

    public @Unsigned long stride;

    public @Unsigned long max_units;

    public @Unsigned long __reserved_1;

    public @Unsigned long access_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int table1; struct { long long unsigned int type; long long unsigned int stride; long long unsigned int max_units; long long unsigned int __reserved_1; long long unsigned int access_type; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_uncore_global_discovery extends Union {
    public @Unsigned long table1;

    public anon_member_of_anon_member_of_uncore_global_discovery anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int num_regs; long long unsigned int ctl_offset; long long unsigned int bit_width; long long unsigned int ctr_offset; long long unsigned int status_offset; long long unsigned int __reserved_1; long long unsigned int access_type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_uncore_unit_discovery extends Struct {
    public @Unsigned long num_regs;

    public @Unsigned long ctl_offset;

    public @Unsigned long bit_width;

    public @Unsigned long ctr_offset;

    public @Unsigned long status_offset;

    public @Unsigned long __reserved_1;

    public @Unsigned long access_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int table1; struct { long long unsigned int num_regs; long long unsigned int ctl_offset; long long unsigned int bit_width; long long unsigned int ctr_offset; long long unsigned int status_offset; long long unsigned int __reserved_1; long long unsigned int access_type; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_uncore_unit_discovery extends Union {
    public @Unsigned long table1;

    public anon_member_of_anon_member_of_uncore_unit_discovery anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long int offs_tai; long long int offs_aux; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_timekeeper extends Union {
    public @OriginalName("ktime_t") long offs_tai;

    public @OriginalName("ktime_t") long offs_aux;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct xen_processor_power power; struct xen_processor_performance perf; unsigned int *pdc; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_xenpf_set_processor_pminfo extends Union {
    public xen_processor_power power;

    public xen_processor_performance perf;

    public @OriginalName("__guest_handle_uint32_t") Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> pdc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct mm_struct *last_user_mm; long unsigned int last_user_mm_spec; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tlb_state extends Union {
    public Ptr<mm_struct> last_user_mm;

    public @Unsigned long last_user_mm_spec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 opcode; int disp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_text_poke_insn extends Struct {
    public char opcode;

    public int disp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int _pt_pad_1; struct page *pmd_huge_pte; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ptdesc extends Struct {
    public @Unsigned long _pt_pad_1;

    public @OriginalName("pgtable_t") Ptr<page> pmd_huge_pte;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct callback_head pt_rcu_head; struct list_head pt_list; struct { long unsigned int _pt_pad_1; struct page *pmd_huge_pte; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ptdesc extends Union {
    public callback_head pt_rcu_head;

    public list_head pt_list;

    public anon_member_of_anon_member_of_ptdesc anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int rbp; long long unsigned int ebp; unsigned int _ebp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_cpu_user_regs extends Union {
    public @Unsigned @OriginalName("uint64_t") long rbp;

    public @Unsigned @OriginalName("uint64_t") long ebp;

    public @Unsigned @OriginalName("uint32_t") int _ebp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; long unsigned int fw_vendor; unsigned int fw_revision; long unsigned int con_in_handle; efi_simple_text_input_protocol *con_in; long unsigned int con_out_handle; efi_simple_text_output_protocol *con_out; long unsigned int stderr_handle; long unsigned int stderr; union { struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; long unsigned int (*get_time)(struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*, struct { unsigned int resolution; unsigned int accuracy; u8 sets_to_zero; }*); long unsigned int (*set_time)(struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*get_wakeup_time)(u8*, u8*, struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*set_wakeup_time)(u8, struct { short unsigned int year; u8 month; u8 day; u8 hour; u8 minute; u8 second; u8 pad1; unsigned int nanosecond; short int timezone; u8 daylight; u8 pad2; }*); long unsigned int (*set_virtual_address_map)(long unsigned int, long unsigned int, unsigned int, struct { unsigned int type; unsigned int pad; long long unsigned int phys_addr; long long unsigned int virt_addr; long long unsigned int num_pages; long long unsigned int attribute; }*); void *convert_pointer; long unsigned int (*get_variable)(short unsigned int*, struct { u8 b[16]; }*, unsigned int*, long unsigned int*, void*); long unsigned int (*get_next_variable)(long unsigned int*, short unsigned int*, struct { u8 b[16]; }*); long unsigned int (*set_variable)(short unsigned int*, struct { u8 b[16]; }*, unsigned int, long unsigned int, void*); long unsigned int (*get_next_high_mono_count)(unsigned int*); void (*reset_system)(int, long unsigned int, long unsigned int, short unsigned int*); long unsigned int (*update_capsule)(struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; }**, long unsigned int, long unsigned int); long unsigned int (*query_capsule_caps)(struct { struct { u8 b[16]; } guid; unsigned int headersize; unsigned int flags; unsigned int imagesize; }**, long unsigned int, long long unsigned int*, int*); long unsigned int (*query_variable_info)(unsigned int, long long unsigned int*, long long unsigned int*, long long unsigned int*); }; struct { struct { long long unsigned int signature; unsigned int revision; unsigned int headersize; unsigned int crc32; unsigned int reserved; } hdr; unsigned int get_time; unsigned int set_time; unsigned int get_wakeup_time; unsigned int set_wakeup_time; unsigned int set_virtual_address_map; unsigned int convert_pointer; unsigned int get_variable; unsigned int get_next_variable; unsigned int set_variable; unsigned int get_next_high_mono_count; unsigned int reset_system; unsigned int update_capsule; unsigned int query_capsule_caps; unsigned int query_variable_info; } mixed_mode; } *runtime; efi_boot_services *boottime; long unsigned int nr_tables; long unsigned int tables; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_efi_system_table_t extends Struct {
    public efi_table_hdr_t hdr;

    public @Unsigned long fw_vendor;

    public @Unsigned int fw_revision;

    public @Unsigned long con_in_handle;

    public @OriginalName("efi_simple_text_input_protocol") Ptr<?> con_in;

    public @Unsigned long con_out_handle;

    public @OriginalName("efi_simple_text_output_protocol") Ptr<?> con_out;

    public @Unsigned long stderr_handle;

    public @Unsigned long stderr;

    public Ptr<efi_runtime_services_t> runtime;

    public @OriginalName("efi_boot_services") Ptr<?> boottime;

    public @Unsigned long nr_tables;

    public @Unsigned long tables;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int enable; long long unsigned int reserved; long long unsigned int pfn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_reference_tsc_msr_and_anon_member_of_hv_vp_assist_msr_contents extends Struct {
    public @Unsigned long enable;

    public @Unsigned long reserved;

    public @Unsigned long pfn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int enable; long long unsigned int reserved; long long unsigned int guest_physical_address; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_x64_msr_hypercall_contents extends Struct {
    public @Unsigned long enable;

    public @Unsigned long reserved;

    public @Unsigned long guest_physical_address;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 target_vtl; u8 use_target_vtl; u8 reserved_z; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_input_vtl extends Struct {
    public char target_vtl;

    public char use_target_vtl;

    public char reserved_z;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int paravisor_present; unsigned int reserved_a1; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ms_hyperv_info extends Struct {
    public @Unsigned int paravisor_present;

    public @Unsigned int reserved_a1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int isolation_config_a; struct { unsigned int paravisor_present; unsigned int reserved_a1; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ms_hyperv_info extends Union {
    public @Unsigned int isolation_config_a;

    public anon_member_of_anon_member_of_ms_hyperv_info anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int reserved; long long unsigned int page_size; long long unsigned int reserved1; long long unsigned int base_large_pfn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_gpa_page_range extends Struct {
    public @Unsigned long reserved;

    public @Unsigned long page_size;

    public @Unsigned long reserved1;

    public @Unsigned long base_large_pfn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int reserved1; unsigned int destination_mode; unsigned int redirection_hint; unsigned int reserved2; unsigned int destination_id; unsigned int msi_base; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_msi_address_register extends Struct {
    public @Unsigned int reserved1;

    public @Unsigned int destination_mode;

    public @Unsigned int redirection_hint;

    public @Unsigned int reserved2;

    public @Unsigned int destination_id;

    public @Unsigned int msi_base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int vector; unsigned int delivery_mode; unsigned int reserved1; unsigned int level_assert; unsigned int trigger_mode; unsigned int reserved2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_msi_data_register extends Struct {
    public @Unsigned int vector;

    public @Unsigned int delivery_mode;

    public @Unsigned int reserved1;

    public @Unsigned int level_assert;

    public @Unsigned int trigger_mode;

    public @Unsigned int reserved2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { union hv_msi_address_register address; union hv_msi_data_register data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_msi_entry extends Struct {
    public hv_msi_address_register address;

    public hv_msi_data_register data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int vector; unsigned int delivery_mode; unsigned int destination_mode; unsigned int delivery_status; unsigned int interrupt_polarity; unsigned int remote_irr; unsigned int trigger_mode; unsigned int interrupt_mask; unsigned int reserved1; unsigned int reserved2; unsigned int destination_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_ioapic_rte extends Struct {
    public @Unsigned int vector;

    public @Unsigned int delivery_mode;

    public @Unsigned int destination_mode;

    public @Unsigned int delivery_status;

    public @Unsigned int interrupt_polarity;

    public @Unsigned int remote_irr;

    public @Unsigned int trigger_mode;

    public @Unsigned int interrupt_mask;

    public @Unsigned int reserved1;

    public @Unsigned int reserved2;

    public @Unsigned int destination_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { union hv_msi_entry msi_entry; union hv_ioapic_rte ioapic_rte; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_interrupt_entry extends Union {
    public hv_msi_entry msi_entry;

    public hv_ioapic_rte ioapic_rte;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int vp_mask; struct hv_vpset vp_set; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_device_interrupt_target extends Union {
    public @Unsigned long vp_mask;

    public hv_vpset vp_set;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 function; u8 device; u8 bus; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_pci_bdf extends Struct {
    public char function;

    public char device;

    public char bus;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 subordinate_bus; u8 secondary_bus; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_pci_bus_range extends Struct {
    public char subordinate_bus;

    public char secondary_bus;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int reserved0; long long unsigned int device_type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_device_id extends Struct {
    public @Unsigned long reserved0;

    public @Unsigned long device_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int rid; union hv_pci_bdf bdf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pci_of_hv_device_id extends Union {
    public @Unsigned @OriginalName("hv_pci_rid") short rid;

    public hv_pci_bdf bdf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int segment_type; short unsigned int non_system_segment; short unsigned int descriptor_privilege_level; short unsigned int present; short unsigned int reserved; short unsigned int available; short unsigned int _long; short unsigned int _default; short unsigned int granularity; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_hv_x64_segment_register extends Struct {
    public @Unsigned short segment_type;

    public @Unsigned short non_system_segment;

    public @Unsigned short descriptor_privilege_level;

    public @Unsigned short present;

    public @Unsigned short reserved;

    public @Unsigned short available;

    public @Unsigned short _long;

    public @Unsigned short _default;

    public @Unsigned short granularity;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int segment_type; short unsigned int non_system_segment; short unsigned int descriptor_privilege_level; short unsigned int present; short unsigned int reserved; short unsigned int available; short unsigned int _long; short unsigned int _default; short unsigned int granularity; }; short unsigned int attributes; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_x64_segment_register extends Union {
    public anon_member_of_anon_member_of_hv_x64_segment_register anon0;

    public @Unsigned short attributes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int callcode; unsigned int isfast; unsigned int reserved1; unsigned int isnested; unsigned int countofelements; unsigned int reserved2; unsigned int repstartindex; unsigned int reserved3; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hypercallinput_of_anon_member_of_hypercall_of_hv_ghcb extends Struct {
    public @Unsigned int callcode;

    public @Unsigned int isfast;

    public @Unsigned int reserved1;

    public @Unsigned int isnested;

    public @Unsigned int countofelements;

    public @Unsigned int reserved2;

    public @Unsigned int repstartindex;

    public @Unsigned int reserved3;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int callstatus; short unsigned int reserved1; unsigned int elementsprocessed; unsigned int reserved2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hypercalloutput_of_anon_member_of_hypercall_of_hv_ghcb extends Struct {
    public @Unsigned short callstatus;

    public @Unsigned short reserved1;

    public @Unsigned int elementsprocessed;

    public @Unsigned int reserved2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { union { struct { unsigned int callcode; unsigned int isfast; unsigned int reserved1; unsigned int isnested; unsigned int countofelements; unsigned int reserved2; unsigned int repstartindex; unsigned int reserved3; }; long long unsigned int asuint64; } hypercallinput; union { struct { short unsigned int callstatus; short unsigned int reserved1; unsigned int elementsprocessed; unsigned int reserved2; }; long long unsigned int asunit64; } hypercalloutput; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hypercall_of_hv_ghcb extends Union {
    public hypercallinput_of_anon_member_of_hypercall_of_hv_ghcb hypercallinput;

    public hypercalloutput_of_anon_member_of_hypercall_of_hv_ghcb hypercalloutput;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { int (*handler)(struct iommu_domain*, struct device*, long unsigned int, int, void*); void *handler_token; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_iommu_domain extends Struct {
    public @OriginalName("iommu_fault_handler_t") Ptr<?> handler;

    public Ptr<?> handler_token;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct iommu_dma_cookie *iova_cookie; struct iommu_dma_msi_cookie *msi_cookie; struct iommufd_hw_pagetable *iommufd_hwpt; struct { int (*handler)(struct iommu_domain*, struct device*, long unsigned int, int, void*); void *handler_token; }; struct { struct mm_struct *mm; int users; struct list_head next; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iommu_domain extends Union {
    public Ptr<iommu_dma_cookie> iova_cookie;

    public Ptr<iommu_dma_msi_cookie> msi_cookie;

    public Ptr<iommufd_hw_pagetable> iommufd_hwpt;

    public anon_member_of_anon_member_of_iommu_domain anon3;

    public anon_member_of_anon_member_of_iommu_domain anon4;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { int si_signo; int si_errno; int si_code; union __sifields _sifields; }; int _si_pad[32]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_siginfo_and_anon_member_of_siginfo_t extends Union {
    public anon_member_of_anon_member_of_siginfo_and_anon_member_of_siginfo_t_and_anon_member_of_kernel_siginfo_and_anon_member_of_kernel_siginfo_t anon0;

    public int @Size(32) [] _si_pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 opcode; struct { u8 type; } jcc; struct { u8 type; u8 asize; } loop; struct { u8 reg; } indirect; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_arch_specific_insn extends Union {
    public char opcode;

    public jcc_of_anon_member_of_arch_specific_insn jcc;

    public loop_of_anon_member_of_arch_specific_insn loop;

    public indirect_of_anon_member_of_arch_specific_insn indirect;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int padding1[44]; unsigned int padding[44]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of__fpstate_32 extends Union {
    public @Unsigned int @Size(44) [] padding1;

    public @Unsigned int @Size(44) [] padding;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int _trapno; short int _addr_lsb; struct { u8 _dummy_bnd[4]; unsigned int _lower; unsigned int _upper; } _addr_bnd; struct { u8 _dummy_pkey[4]; unsigned int _pkey; } _addr_pkey; struct { unsigned int _data; unsigned int _type; unsigned int _flags; } _perf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of__sigfault_of__sifields_of_compat_siginfo_and__sifields_of_compat_siginfo_t extends Union {
    public int _trapno;

    public short _addr_lsb;

    public _addr_bnd_of_anon_member_of__sigfault_of__sifields_of_compat_siginfo_and__sifields_of_compat_siginfo_t _addr_bnd;

    public _addr_pkey_of_anon_member_of__sigfault_of__sifields_of_compat_siginfo_and__sifields_of_compat_siginfo_t _addr_pkey;

    public _perf_of_anon_member_of__sigfault_of__sifields_of_compat_siginfo_and__sifields_of_compat_siginfo_t _perf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { enum _cache_table_type c_type; enum _tlb_table_type t_type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_leaf_0x2_table extends Union {
    public _cache_table_type c_type;

    public _tlb_table_type t_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int line_size; unsigned int lines_per_tag; unsigned int assoc; unsigned int size_in_kb; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_l1_cache extends Struct {
    public @Unsigned int line_size;

    public @Unsigned int lines_per_tag;

    public @Unsigned int assoc;

    public @Unsigned int size_in_kb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int line_size; unsigned int lines_per_tag; unsigned int assoc; unsigned int size_in_kb; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_l2_cache extends Struct {
    public @Unsigned int line_size;

    public @Unsigned int lines_per_tag;

    public @Unsigned int assoc;

    public @Unsigned int size_in_kb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int line_size; unsigned int lines_per_tag; unsigned int assoc; unsigned int res; unsigned int size_encoded; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_l3_cache extends Struct {
    public @Unsigned int line_size;

    public @Unsigned int lines_per_tag;

    public @Unsigned int assoc;

    public @Unsigned int res;

    public @Unsigned int size_encoded;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int rev; unsigned int stepping; unsigned int model; unsigned int __reserved; unsigned int ext_model; unsigned int ext_fam; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_zen_patch_rev extends Struct {
    public @Unsigned int rev;

    public @Unsigned int stepping;

    public @Unsigned int model;

    public @Unsigned int __reserved;

    public @Unsigned int ext_model;

    public @Unsigned int ext_fam;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int stepping; unsigned int model; unsigned int family; unsigned int __reserved0; unsigned int ext_model; unsigned int ext_fam; unsigned int __reserved1; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_cpuid_1_eax extends Struct {
    public @Unsigned int stepping;

    public @Unsigned int model;

    public @Unsigned int family;

    public @Unsigned int __reserved0;

    public @Unsigned int ext_model;

    public @Unsigned int ext_fam;

    public @Unsigned int __reserved1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head private_list; struct callback_head callback_head; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_xa_node extends Union {
    public list_head private_list;

    public callback_head callback_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int clock_low; unsigned int clock_high; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_vmware_steal_time extends Struct {
    public @Unsigned int clock_low;

    public @Unsigned int clock_high;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int clock; struct { unsigned int clock_low; unsigned int clock_high; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vmware_steal_time extends Union {
    public @Unsigned long clock;

    public anon_member_of_anon_member_of_vmware_steal_time anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int build_number; unsigned int minor_version; unsigned int major_version; unsigned int service_pack; unsigned int service_number; unsigned int service_branch; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_hypervisor_version_info extends Struct {
    public @Unsigned int build_number;

    public @Unsigned int minor_version;

    public @Unsigned int major_version;

    public @Unsigned int service_pack;

    public @Unsigned int service_number;

    public @Unsigned int service_branch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *private; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sched_domain extends Union {
    public Ptr<?> _private;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int vector; long long unsigned int delivery_mode; long long unsigned int dest_mode_logical; long long unsigned int delivery_status; long long unsigned int active_low; long long unsigned int irr; long long unsigned int is_level; long long unsigned int masked; long long unsigned int reserved_0; long long unsigned int reserved_1; long long unsigned int virt_destid_8_14; long long unsigned int destid_0_7; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_IO_APIC_route_entry extends Struct {
    public @Unsigned long vector;

    public @Unsigned long delivery_mode;

    public @Unsigned long dest_mode_logical;

    public @Unsigned long delivery_status;

    public @Unsigned long active_low;

    public @Unsigned long irr;

    public @Unsigned long is_level;

    public @Unsigned long masked;

    public @Unsigned long reserved_0;

    public @Unsigned long reserved_1;

    public @Unsigned long virt_destid_8_14;

    public @Unsigned long destid_0_7;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int vector; long long unsigned int delivery_mode; long long unsigned int dest_mode_logical; long long unsigned int delivery_status; long long unsigned int active_low; long long unsigned int irr; long long unsigned int is_level; long long unsigned int masked; long long unsigned int reserved_0; long long unsigned int reserved_1; long long unsigned int virt_destid_8_14; long long unsigned int destid_0_7; }; struct { long long unsigned int ir_shared_0; long long unsigned int ir_zero; long long unsigned int ir_index_15; long long unsigned int ir_shared_1; long long unsigned int ir_reserved_0; long long unsigned int ir_format; long long unsigned int ir_index_0_14; }; struct { long long unsigned int w1; long long unsigned int w2; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_IO_APIC_route_entry extends Union {
    public anon_member_of_anon_member_of_IO_APIC_route_entry anon0;

    public anon_member_of_anon_member_of_IO_APIC_route_entry anon1;

    public anon_member_of_anon_member_of_IO_APIC_route_entry anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const void *pointer; union { u8 u8_data[8]; short unsigned int u16_data[4]; unsigned int u32_data[2]; long long unsigned int u64_data[1]; const u8* str[1]; } value; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_property_entry extends Union {
    public Ptr<?> pointer;

    public value_of_anon_member_of_property_entry value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 op[3]; int offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ftrace_op_code_union extends Struct {
    public char @Size(3) [] op;

    public int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *buf; void *kbuf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kexec_segment extends Union {
    public Ptr<?> buf;

    public Ptr<?> kbuf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { qspinlock lock; unsigned int value; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hpet_lock extends Struct {
    public @OriginalName("arch_spinlock_t") qspinlock lock;

    public @Unsigned int value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 addr_recv; u8 addr_dest; u8 padding0[2]; unsigned int padding1[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_serial_rs485 extends Struct {
    public char addr_recv;

    public char addr_dest;

    public char @Size(2) [] padding0;

    public @Unsigned int @Size(4) [] padding1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int padding[5]; struct { u8 addr_recv; u8 addr_dest; u8 padding0[2]; unsigned int padding1[4]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_serial_rs485 extends Union {
    public @Unsigned int @Size(5) [] padding;

    public anon_member_of_anon_member_of_serial_rs485 anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { u8 b[16]; } guid; void *table; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_efi_config_table_t extends Struct {
    public @OriginalName("efi_guid_t") uuid_t guid;

    public Ptr<?> table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int hub_version; long long unsigned int partition_id; long long unsigned int coherence_id; long long unsigned int region_size; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_partition_info_u extends Struct {
    public @Unsigned long hub_version;

    public @Unsigned long partition_id;

    public @Unsigned long coherence_id;

    public @Unsigned long region_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_value; u8 value[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_array extends Struct {
    public lockdep_map_p __empty_value;

    public char @Size(0) [] value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { } __empty_value; u8 value[0]; }; struct { struct { } __empty_ptrs; void* ptrs[0]; }; struct { struct { } __empty_pptrs; void* pptrs[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_array extends Union {
    public anon_member_of_anon_member_of_bpf_array anon0;

    public anon_member_of_anon_member_of_bpf_array anon1;

    public anon_member_of_anon_member_of_bpf_array anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int class; unsigned int classid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_tcf_result extends Struct {
    public @Unsigned long _class;

    public @Unsigned int classid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long unsigned int class; unsigned int classid; }; const struct tcf_proto *goto_tp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tcf_result extends Union {
    public anon_member_of_anon_member_of_tcf_result anon0;

    public Ptr<tcf_proto> goto_tp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ipv4_nh; struct in6_addr ipv6_nh; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_nh_params extends Union {
    public @Unsigned int ipv4_nh;

    public in6_addr ipv6_nh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int assigned; long long unsigned int pagesize; long long unsigned int immutable; long long unsigned int rsvd1; long long unsigned int gpa; long long unsigned int asid; long long unsigned int vmsa; long long unsigned int validated; long long unsigned int rsvd2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_rmpentry_raw extends Struct {
    public @Unsigned long assigned;

    public @Unsigned long pagesize;

    public @Unsigned long immutable;

    public @Unsigned long rsvd1;

    public @Unsigned long gpa;

    public @Unsigned long asid;

    public @Unsigned long vmsa;

    public @Unsigned long validated;

    public @Unsigned long rsvd2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int assigned; long long unsigned int pagesize; long long unsigned int immutable; long long unsigned int rsvd1; long long unsigned int gpa; long long unsigned int asid; long long unsigned int vmsa; long long unsigned int validated; long long unsigned int rsvd2; }; long long unsigned int lo; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_rmpentry_raw extends Union {
    public anon_member_of_anon_member_of_rmpentry_raw anon0;

    public @Unsigned long lo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_reserved_areas; struct tdmr_reserved_area reserved_areas[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tdmr_info extends Struct {
    public lockdep_map_p __empty_reserved_areas;

    public tdmr_reserved_area @Size(0) [] reserved_areas;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int head; unsigned int tail; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_pipe_inode_info_and_anon_member_of_pipe_index extends Struct {
    public @Unsigned @OriginalName("pipe_index_t") int head;

    public @Unsigned @OriginalName("pipe_index_t") int tail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int head_tail; struct { unsigned int head; unsigned int tail; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pipe_inode_info extends Union {
    public @Unsigned long head_tail;

    public anon_member_of_anon_member_of_pipe_inode_info_and_anon_member_of_pipe_index anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void (*func)(long unsigned int); void (*callback)(struct tasklet_struct*); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tasklet_struct extends Union {
    public Ptr<?> func;

    public Ptr<?> callback;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int nr; long long unsigned int args[6]; } entry; struct { long long int rval; u8 is_error; } exit; struct { long long unsigned int nr; long long unsigned int args[6]; unsigned int ret_data; unsigned int reserved2; } seccomp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ptrace_syscall_info extends Union {
    public entry_of_anon_member_of_ptrace_syscall_info entry;

    public exit_of_anon_member_of_ptrace_syscall_info exit;

    public seccomp_of_anon_member_of_ptrace_syscall_info seccomp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct pid *it_pid; struct task_struct *it_process; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_k_itimer extends Union {
    public Ptr<pid> it_pid;

    public Ptr<task_struct> it_process;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head entry; struct hlist_node hentry; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_worker extends Union {
    public list_head entry;

    public hlist_node hentry;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct task_struct *donor; struct task_struct *curr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_rq extends Union {
    public Ptr<task_struct> donor;

    public Ptr<task_struct> curr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int cmd_op; unsigned int __pad1; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_io_uring_sqe extends Struct {
    public @Unsigned int cmd_op;

    public @Unsigned int __pad1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int off; long long unsigned int addr2; struct { unsigned int cmd_op; unsigned int __pad1; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_uring_sqe extends Union {
    public @Unsigned long off;

    public @Unsigned long addr2;

    public anon_member_of_anon_member_of_io_uring_sqe anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct llist_head task_list; struct callback_head task_work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_uring_task extends Struct {
    public llist_head task_list;

    public callback_head task_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int flags; unsigned int drain_next; unsigned int restricted; unsigned int off_timeout_used; unsigned int drain_active; unsigned int has_evfd; unsigned int task_complete; unsigned int lockless_cq; unsigned int syscall_iopoll; unsigned int poll_activated; unsigned int drain_disabled; unsigned int compat; unsigned int iowq_limits_set; struct task_struct *submitter_task; struct io_rings *rings; struct percpu_ref refs; int clockid; enum tk_offsets clock_offset; enum task_work_notify_mode notify_method; unsigned int sq_thread_idle; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_ring_ctx extends Struct {
    public @Unsigned int flags;

    public @Unsigned int drain_next;

    public @Unsigned int restricted;

    public @Unsigned int off_timeout_used;

    public @Unsigned int drain_active;

    public @Unsigned int has_evfd;

    public @Unsigned int task_complete;

    public @Unsigned int lockless_cq;

    public @Unsigned int syscall_iopoll;

    public @Unsigned int poll_activated;

    public @Unsigned int drain_disabled;

    public @Unsigned int compat;

    public @Unsigned int iowq_limits_set;

    public Ptr<task_struct> submitter_task;

    public Ptr<io_rings> rings;

    public percpu_ref refs;

    public @OriginalName("clockid_t") int clockid;

    public tk_offsets clock_offset;

    public task_work_notify_mode notify_method;

    public @Unsigned int sq_thread_idle;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int flags; int fd; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_cqe extends Union {
    public @Unsigned int flags;

    public int fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct file *file; struct io_cmd_data cmd; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_kiocb extends Union {
    public Ptr<file> file;

    public io_cmd_data cmd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct bpf_map *map_ptr; unsigned int map_uid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_reg_state extends Struct {
    public Ptr<bpf_map> map_ptr;

    public @Unsigned int map_uid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct btf *btf; unsigned int btf_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_reg_state_and_anon_member_of_anon_member_of_btf_var_of_anon_member_of_bpf_insn_aux_data extends Struct {
    public Ptr<btf> btf;

    public @Unsigned int btf_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int range; struct { struct bpf_map *map_ptr; unsigned int map_uid; }; struct { struct btf *btf; unsigned int btf_id; }; struct { unsigned int mem_size; unsigned int dynptr_id; }; struct { enum bpf_dynptr_type type; _Bool first_slot; } dynptr; struct { struct btf *btf; unsigned int btf_id; enum bpf_iter_state state; int depth; } iter; struct { enum kfunc_class_of_irq_of_anon_member_of_bpf_reg_state kfunc_class; } irq; struct { long unsigned int raw1; long unsigned int raw2; } raw; unsigned int subprogno; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_reg_state extends Union {
    public int range;

    public anon_member_of_anon_member_of_bpf_reg_state anon1;

    public anon_member_of_anon_member_of_bpf_reg_state_and_anon_member_of_anon_member_of_btf_var_of_anon_member_of_bpf_insn_aux_data anon2;

    public anon_member_of_anon_member_of_bpf_reg_state anon3;

    public dynptr_of_anon_member_of_bpf_reg_state dynptr;

    public iter_of_anon_member_of_bpf_reg_state iter;

    public irq_of_anon_member_of_bpf_reg_state irq;

    public raw_of_anon_member_of_bpf_reg_state raw;

    public @Unsigned int subprogno;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int map_index; unsigned int map_off; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_insn_aux_data extends Struct {
    public @Unsigned int map_index;

    public @Unsigned int map_off;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct btf *btf; unsigned int btf_id; }; unsigned int mem_size; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_btf_var_of_anon_member_of_bpf_insn_aux_data extends Union {
    public anon_member_of_anon_member_of_bpf_reg_state_and_anon_member_of_anon_member_of_btf_var_of_anon_member_of_bpf_insn_aux_data anon0;

    public @Unsigned int mem_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { enum bpf_reg_type ptr_type; struct bpf_map_ptr_state map_ptr_state; int call_imm; unsigned int alu_limit; struct { unsigned int map_index; unsigned int map_off; }; struct { enum bpf_reg_type reg_type; union { struct { struct btf *btf; unsigned int btf_id; }; unsigned int mem_size; }; } btf_var; struct bpf_loop_inline_state loop_inline_state; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_insn_aux_data extends Union {
    public bpf_reg_type ptr_type;

    public bpf_map_ptr_state map_ptr_state;

    public int call_imm;

    public @Unsigned int alu_limit;

    public anon_member_of_anon_member_of_bpf_insn_aux_data anon4;

    public btf_var_of_anon_member_of_bpf_insn_aux_data btf_var;

    public bpf_loop_inline_state loop_inline_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int mem_size; unsigned int btf_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_subprog_arg_info extends Union {
    public @Unsigned int mem_size;

    public @Unsigned int btf_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_idmap idmap_scratch; struct bpf_idset idset_scratch; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_verifier_env extends Union {
    public bpf_idmap idmap_scratch;

    public bpf_idset idset_scratch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const u8 *src; struct folio *sfolio; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acomp_req_chain extends Union {
    public Ptr<java.lang.Character> src;

    public Ptr<folio> sfolio;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct scatterlist *src; const u8 *svirt; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acomp_req_and_anon_member_of_ahash_request extends Union {
    public Ptr<scatterlist> src;

    public Ptr<java.lang.Character> svirt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct scatterlist *dst; u8 *dvirt; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acomp_req extends Union {
    public Ptr<scatterlist> dst;

    public Ptr<java.lang.Character> dvirt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int prio; unsigned int req_prio; unsigned int unsafe; unsigned int unsafe_takeover; unsigned int cpu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_nbcon_state extends Struct {
    public @Unsigned int prio;

    public @Unsigned int req_prio;

    public @Unsigned int unsafe;

    public @Unsigned int unsafe_takeover;

    public @Unsigned int cpu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int atom; struct { unsigned int prio; unsigned int req_prio; unsigned int unsafe; unsigned int unsafe_takeover; unsigned int cpu; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nbcon_state extends Union {
    public @Unsigned int atom;

    public anon_member_of_anon_member_of_nbcon_state anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int uvalue; long long int svalue; long long unsigned int ptr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_rtc_param extends Union {
    public @Unsigned long uvalue;

    public long svalue;

    public @Unsigned long ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 active; u8 migrator; short unsigned int seq; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tmigr_state extends Struct {
    public char active;

    public char migrator;

    public @Unsigned short seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct vdso_timestamp basetime[12]; struct timens_offset offset[12]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vdso_clock extends Union {
    public vdso_timestamp @Size(12) [] basetime;

    public timens_offset @Size(12) [] offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct mm_struct *mm; long long unsigned int __tmp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_private_of_futex_key extends Union {
    public Ptr<mm_struct> mm;

    public @Unsigned long __tmp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct seq_file *seq; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter_meta extends Union {
    public Ptr<seq_file> seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_iter_meta *meta; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__bpf_link_and_anon_member_of_bpf_iter__bpf_map_and_anon_member_of_bpf_iter__bpf_map_elem extends Union {
    public Ptr<bpf_iter_meta> meta;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct kallsym_iter *ksym; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__ksym extends Union {
    public Ptr<kallsym_iter> ksym;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_storage_buffer *buf; void *percpu_buf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_cgroup_storage extends Union {
    public Ptr<bpf_storage_buffer> buf;

    public Ptr<?> percpu_buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int out_len; unsigned int in2_len; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kernel_pkey_params_and_anon_member_of_keyctl_pkey_params extends Union {
    public @Unsigned int out_len;

    public @Unsigned int in2_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int ss_family; u8 __data[126]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of___kernel_sockaddr_storage extends Struct {
    public @Unsigned @OriginalName("__kernel_sa_family_t") short ss_family;

    public char @Size(126) [] __data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int ss_family; u8 __data[126]; }; void *__align; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of___kernel_sockaddr_storage extends Union {
    public anon_member_of_anon_member_of___kernel_sockaddr_storage anon0;

    public Ptr<?> __align;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int version; unsigned int feature_bitmap; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_audit_status extends Union {
    public @Unsigned int version;

    public @Unsigned int feature_bitmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_ptr; void* ptr[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_net_generic extends Struct {
    public lockdep_map_p __empty_ptr;

    public Ptr<?> @Size(0) [] ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int len; struct callback_head rcu; } s; struct { struct { } __empty_ptr; void* ptr[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_net_generic extends Union {
    public s_of_anon_member_of_net_generic s;

    public anon_member_of_anon_member_of_net_generic anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int fE; struct { long long unsigned int val; } effective; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_audit_cap_data extends Union {
    public @Unsigned int fE;

    public kernel_cap_t effective;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { int nargs; long int args[6]; } socketcall; struct { struct { unsigned int val; } uid; struct { unsigned int val; } gid; short unsigned int mode; struct lsm_prop oprop; int has_perm; unsigned int perm_uid; unsigned int perm_gid; short unsigned int perm_mode; long unsigned int qbytes; } ipc; struct { int mqdes; struct mq_attr mqstat; } mq_getsetattr; struct { int mqdes; int sigev_signo; } mq_notify; struct { int mqdes; long unsigned int msg_len; unsigned int msg_prio; struct timespec64 abs_timeout; } mq_sendrecv; struct { int oflag; short unsigned int mode; struct mq_attr attr; } mq_open; struct { int pid; struct audit_cap_data cap; } capset; struct { int fd; int flags; } mmap; struct open_how openat2; struct { int argc; } execve; struct { const u8 *name; } module; struct { struct audit_ntp_data ntp_data; struct timespec64 tk_injoffset; } time; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_audit_context extends Union {
    public socketcall_of_anon_member_of_audit_context socketcall;

    public ipc_of_anon_member_of_audit_context ipc;

    public mq_getsetattr_of_anon_member_of_audit_context mq_getsetattr;

    public mq_notify_of_anon_member_of_audit_context mq_notify;

    public mq_sendrecv_of_anon_member_of_audit_context mq_sendrecv;

    public mq_open_of_anon_member_of_audit_context mq_open;

    public capset_of_anon_member_of_audit_context capset;

    public mmap_of_anon_member_of_audit_context mmap;

    public open_how openat2;

    public execve_of_anon_member_of_audit_context execve;

    public module_of_anon_member_of_audit_context module;

    public time_of_anon_member_of_audit_context time;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 *lsm_str; void *lsm_rule; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_audit_field extends Struct {
    public String lsm_str;

    public Ptr<?> lsm_rule;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int val; struct { unsigned int val; } uid; struct { unsigned int val; } gid; struct { u8 *lsm_str; void *lsm_rule; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_audit_field extends Union {
    public @Unsigned int val;

    public kuid_t uid;

    public kgid_t gid;

    public anon_member_of_anon_member_of_audit_field anon3;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *obj; struct fsnotify_mark_connector *destroy_next; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fsnotify_mark_connector extends Union {
    public Ptr<?> obj;

    public Ptr<fsnotify_mark_connector> destroy_next;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *private; struct inotify_group_private_data inotify_data; struct fanotify_group_private_data fanotify_data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fsnotify_group extends Union {
    public Ptr<?> _private;

    public inotify_group_private_data inotify_data;

    public fanotify_group_private_data fanotify_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { _Bool setfd; int ret; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_seccomp_kaddfd extends Union {
    public boolean setfd;

    public int ret;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 ctx[48]; void* user_ptr[2]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_genl_info extends Union {
    public char @Size(48) [] ctx;

    public Ptr<?> @Size(2) [] user_ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { int (*pre_doit)(const struct genl_split_ops*, struct sk_buff*, struct genl_info*); int (*doit)(struct sk_buff*, struct genl_info*); void (*post_doit)(const struct genl_split_ops*, struct sk_buff*, struct genl_info*); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_genl_split_ops extends Struct {
    public Ptr<?> pre_doit;

    public Ptr<?> doit;

    public Ptr<?> post_doit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { int (*pre_doit)(const struct genl_split_ops*, struct sk_buff*, struct genl_info*); int (*doit)(struct sk_buff*, struct genl_info*); void (*post_doit)(const struct genl_split_ops*, struct sk_buff*, struct genl_info*); }; struct { int (*start)(struct netlink_callback*); int (*dumpit)(struct sk_buff*, struct netlink_callback*); int (*done)(struct netlink_callback*); }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_genl_split_ops extends Union {
    public anon_member_of_anon_member_of_genl_split_ops anon0;

    public anon_member_of_anon_member_of_genl_split_ops anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long int counter; } sum; unsigned int offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tracing_map_field extends Union {
    public atomic64_t sum;

    public @Unsigned int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct fgraph_ent_args ent; struct fgraph_retaddr_ent_entry rent; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fgraph_data extends Union {
    public fgraph_ent_args ent;

    public fgraph_retaddr_ent_entry rent;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head queuelist; struct request *rq_next; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_request extends Union {
    public list_head queuelist;

    public Ptr<request> rq_next;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { spinlock lock; struct list_head dispatch; long unsigned int state; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_blk_mq_hw_ctx extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public list_head dispatch;

    public @Unsigned long state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct trace_event_file *file; struct event_mod_load *event_mod; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_set_event_iter extends Union {
    public Ptr<trace_event_file> file;

    public Ptr<event_mod_load> event_mod;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct callback_head rcu; struct rcu_work rwork; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_filter_head extends Union {
    public callback_head rcu;

    public rcu_work rwork;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int size; int offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_fetch_insn extends Struct {
    public @Unsigned int size;

    public int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int param; struct { unsigned int size; int offset; }; struct { u8 basesize; u8 lshift; u8 rshift; }; long unsigned int immediate; void *data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fetch_insn extends Union {
    public @Unsigned int param;

    public anon_member_of_anon_member_of_fetch_insn anon1;

    public anon_member_of_anon_member_of_fetch_insn anon2;

    public @Unsigned long immediate;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 *event; u8 *event_system; } match_data; struct { u8 *var_str; struct hist_field *var_ref; struct hist_field *track_var; _Bool (*check_val)(long long unsigned int, long long unsigned int); void (*save_data)(struct hist_trigger_data*, struct tracing_map_elt*, struct trace_buffer*, void*, struct ring_buffer_event*, void*, struct action_data*, long long unsigned int*); } track_data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_action_data extends Union {
    public match_data_of_anon_member_of_action_data match_data;

    public track_data_of_anon_member_of_action_data track_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *allocator; struct page_pool *page_pool; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_xdp_mem_allocator extends Union {
    public Ptr<?> allocator;

    public Ptr<page_pool> page_pool;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_flow_keys *flow_keys; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of___sk_buff extends Union {
    public Ptr<bpf_flow_keys> flow_keys;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_sock *sk; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of___sk_buff_and_anon_member_of_anon_member_of_bpf_sk_lookup_and_anon_member_of_bpf_sock_addr extends Union {
    public Ptr<bpf_sock> sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int ipv4_src; unsigned int ipv4_dst; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_flow_keys extends Struct {
    public @Unsigned @OriginalName("__be32") int ipv4_src;

    public @Unsigned @OriginalName("__be32") int ipv4_dst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int ipv4_src; unsigned int ipv4_dst; }; struct { unsigned int ipv6_src[4]; unsigned int ipv6_dst[4]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_flow_keys extends Union {
    public anon_member_of_anon_member_of_bpf_flow_keys anon0;

    public anon_member_of_anon_member_of_bpf_flow_keys anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 spi; u8 regno; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_linked_reg extends Union {
    public char spi;

    public char regno;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct callback_head rcu; struct work_struct delete_work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_async_cb extends Union {
    public callback_head rcu;

    public work_struct delete_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_async_cb *cb; struct bpf_hrtimer *timer; struct bpf_work *work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_async_kern extends Union {
    public Ptr<bpf_async_cb> cb;

    public Ptr<bpf_hrtimer> timer;

    public Ptr<bpf_work> work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int *bits; long long unsigned int bits_copy; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter_bits_kern extends Union {
    public Ptr<java.lang. @Unsigned Long> bits;

    public @Unsigned long bits_copy;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_map *map; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__bpf_map_and_anon_member_of_bpf_iter__bpf_map_elem_and_anon_member_of_bpf_iter__bpf_sk_storage_map extends Union {
    public Ptr<bpf_map> map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct task_struct *task; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__task_and_anon_member_of_bpf_iter__task_file_and_anon_member_of_bpf_iter__task_vma extends Union {
    public Ptr<task_struct> task;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct file *file; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__task_file extends Union {
    public Ptr<file> file;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct vm_area_struct *vma; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__task_vma extends Union {
    public Ptr<vm_area_struct> vma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_prog *prog; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__bpf_prog extends Union {
    public Ptr<bpf_prog> prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_link *link; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__bpf_link extends Union {
    public Ptr<bpf_link> link;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *key; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__bpf_map_elem_and_anon_member_of_bpf_iter__sockmap extends Union {
    public Ptr<?> key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *value; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__bpf_map_elem_and_anon_member_of_bpf_iter__bpf_sk_storage_map extends Union {
    public Ptr<?> value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_common_lru common_lru; struct bpf_lru_list *percpu_lru; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_lru extends Union {
    public bpf_common_lru common_lru;

    public Ptr<bpf_lru_list> percpu_lru;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct pcpu_freelist freelist; struct bpf_lru lru; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_htab extends Union {
    public pcpu_freelist freelist;

    public bpf_lru lru;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct pcpu_freelist_node fnode; struct htab_elem *batch_flink; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_htab_elem extends Union {
    public pcpu_freelist_node fnode;

    public Ptr<htab_elem> batch_flink;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { void *padding; union { struct pcpu_freelist_node fnode; struct htab_elem *batch_flink; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_htab_elem extends Struct {
    public Ptr<?> padding;

    @InlineUnion(17312)
    public pcpu_freelist_node fnode;

    @InlineUnion(17312)
    public Ptr<htab_elem> batch_flink;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct hlist_nulls_node hash_node; struct { void *padding; union { struct pcpu_freelist_node fnode; struct htab_elem *batch_flink; }; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_htab_elem extends Union {
    public hlist_nulls_node hash_node;

    public anon_member_of_anon_member_of_htab_elem anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_lpm_trie_key_hdr hdr; unsigned int prefixlen; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_lpm_trie_key_u8 extends Union {
    public bpf_lpm_trie_key_hdr hdr;

    public @Unsigned int prefixlen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct callback_head rcu; struct hlist_node free_node; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_local_storage_elem extends Union {
    public callback_head rcu;

    public hlist_node free_node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sk_msg_md_and_anon_member_of_sk_reuseport_md extends Union {
    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct bpf_sock *migrating_sk; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sk_reuseport_md extends Union {
    public Ptr<bpf_sock> migrating_sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int args[4]; unsigned int reply; unsigned int replylong[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_sock_ops extends Union {
    public @Unsigned int @Size(4) [] args;

    public @Unsigned int reply;

    public @Unsigned int @Size(4) [] replylong;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *optval; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_sockopt extends Union {
    public Ptr<?> optval;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { union { struct bpf_sock *sk; }; long long unsigned int cookie; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_sk_lookup extends Union {
    @InlineUnion(16859)
    public Ptr<bpf_sock> sk;

    public @Unsigned long cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int args[4]; unsigned int reply; unsigned int replylong[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_sock_ops_kern extends Union {
    public @Unsigned int @Size(4) [] args;

    public @Unsigned int reply;

    public @Unsigned int @Size(4) [] replylong;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int rt_gw4; struct in6_addr rt_gw6; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_rtable extends Union {
    public @Unsigned @OriginalName("__be32") int rt_gw4;

    public in6_addr rt_gw6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void (*destructor)(struct sock*); struct sock *saved_sk; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ip_ra_chain extends Union {
    public Ptr<?> destructor;

    public Ptr<sock> saved_sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head fib6_siblings; struct list_head nh_list; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fib6_info extends Union {
    public list_head fib6_siblings;

    public list_head nh_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct hlist_node gclist; struct hlist_node bydst; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_xfrm_state extends Union {
    public hlist_node gclist;

    public hlist_node bydst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int type_id; } kptr; struct { const u8 *node_name; unsigned int value_btf_id; } graph_root; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_btf_field_info extends Union {
    public kptr_of_anon_member_of_btf_field_info kptr;

    public graph_root_of_anon_member_of_btf_field_info graph_root;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct skb_shared_hwtstamps hwtstamps; struct xsk_tx_metadata_compl xsk_meta; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_skb_shared_info extends Union {
    public skb_shared_hwtstamps hwtstamps;

    public xsk_tx_metadata_compl xsk_meta;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int xdp_frags_size; unsigned int xdp_frags_truesize; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_skb_shared_info extends Struct {
    public @Unsigned int xdp_frags_size;

    public @Unsigned int xdp_frags_truesize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct hlist_head head; struct hlist_nulls_head nulls_head; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_udp_hslot extends Union {
    public hlist_head head;

    public hlist_nulls_head nulls_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int offset; long long unsigned int ip; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_stack_build_id extends Union {
    public @Unsigned long offset;

    public @Unsigned long ip;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct cgroup *cgroup; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__cgroup extends Union {
    public Ptr<cgroup> cgroup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int pkt_len; short unsigned int slave_dev_queue_mapping; short unsigned int tc_classid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_qdisc_skb_cb extends Struct {
    public @Unsigned int pkt_len;

    public @Unsigned short slave_dev_queue_mapping;

    public @Unsigned short tc_classid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct kmem_cache *s; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__kmem_cache extends Union {
    public Ptr<kmem_cache> s;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *vaddr_iomem; void *vaddr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iosys_map extends Union {
    public Ptr<?> vaddr_iomem;

    public Ptr<?> vaddr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head cb_list; long long int timestamp; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dma_fence extends Union {
    public list_head cb_list;

    public @OriginalName("ktime_t") long timestamp;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct dma_buf *dmabuf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__dmabuf extends Union {
    public Ptr<dma_buf> dmabuf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long unsigned int pte; } *ptep; struct { long unsigned int pud; } *pudp; struct { long unsigned int pmd; } *pmdp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_folio_walk extends Union {
    public Ptr<pte_t> ptep;

    public Ptr<pud_t> pudp;

    public Ptr<pmd_t> pmdp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct callback_head rcu; long unsigned int type_filter[1]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_watch_filter extends Union {
    public callback_head rcu;

    public @Unsigned long @Size(1) [] type_filter;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct callback_head rcu; unsigned int info_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_watch extends Union {
    public callback_head rcu;

    public @Unsigned int info_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct list_head shrinklist; struct list_head swaplist; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_shmem_inode_info extends Struct {
    public list_head shrinklist;

    public list_head swaplist;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct offset_ctx dir_offsets; struct { struct list_head shrinklist; struct list_head swaplist; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_shmem_inode_info extends Union {
    public offset_ctx dir_offsets;

    public anon_member_of_anon_member_of_shmem_inode_info anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_raw; unsigned int raw[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_fid extends Struct {
    public lockdep_map_p __empty_raw;

    public @Unsigned int @Size(0) [] raw;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int ino; unsigned int gen; unsigned int parent_ino; unsigned int parent_gen; } i32; struct { long long unsigned int ino; unsigned int gen; } i64; struct { unsigned int block; short unsigned int partref; short unsigned int parent_partref; unsigned int generation; unsigned int parent_block; unsigned int parent_generation; } udf; struct { struct { } __empty_raw; unsigned int raw[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fid extends Union {
    public i32_of_anon_member_of_fid i32;

    public i64_of_anon_member_of_fid i64;

    public udf_of_anon_member_of_fid udf;

    public anon_member_of_anon_member_of_fid anon3;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { void *freelist; long unsigned int counter; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_freelist_aba_t extends Struct {
    public Ptr<?> freelist;

    public @Unsigned long counter;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct slab *next; int slabs; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_slab extends Struct {
    public Ptr<slab> next;

    public int slabs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head slab_list; struct { struct slab *next; int slabs; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_slab extends Union {
    public list_head slab_list;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_slab anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int inuse; unsigned int objects; unsigned int frozen; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_anon_member_of_anon_member_of_slab extends Struct {
    public @Unsigned int inuse;

    public @Unsigned int objects;

    public @Unsigned int frozen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int counters; struct { unsigned int inuse; unsigned int objects; unsigned int frozen; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_anon_member_of_slab extends Union {
    public @Unsigned long counters;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_anon_member_of_anon_member_of_slab anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { union { struct list_head slab_list; struct { struct slab *next; int slabs; }; }; union { struct { void *freelist; union { long unsigned int counters; struct { unsigned int inuse; unsigned int objects; unsigned int frozen; }; }; }; union { struct { void *freelist; long unsigned int counter; }; __int128 unsigned full; } freelist_counter; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_slab extends Struct {
    @InlineUnion(19360)
    public list_head slab_list;

    @InlineUnion(19360)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_slab anon0$1;

    @InlineUnion(19364)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_slab anon1$0;

    @InlineUnion(19364)
    public freelist_aba_t freelist_counter;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { union { struct list_head slab_list; struct { struct slab *next; int slabs; }; }; union { struct { void *freelist; union { long unsigned int counters; struct { unsigned int inuse; unsigned int objects; unsigned int frozen; }; }; }; union { struct { void *freelist; long unsigned int counter; }; __int128 unsigned full; } freelist_counter; }; }; struct callback_head callback_head; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_slab extends Union {
    public anon_member_of_anon_member_of_slab anon0;

    public callback_head callback_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct anon_vma_chain"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_vma_chain extends Struct {
    public Ptr<vm_area_struct> vma;

    public Ptr<anon_vma> anon_vma;

    public list_head same_vma;

    public rb_node rb;

    public @Unsigned long rb_subtree_last;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct page **pages; struct folio **folios; void **entries; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pages_or_folios extends Union {
    public Ptr<Ptr<page>> pages;

    public Ptr<Ptr<folio>> folios;

    public Ptr<Ptr<?>> entries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int subtree_max_size; struct vm_struct *vm; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vmap_area extends Union {
    public @Unsigned long subtree_max_size;

    public Ptr<vm_struct> vm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long unsigned int max_pages; } s; struct { long unsigned int unit_pages; } d; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_memory_group extends Union {
    public s_of_anon_member_of_memory_group s;

    public d_of_anon_member_of_memory_group d;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { void **freelist; long unsigned int tid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_kmem_cache_cpu extends Struct {
    public Ptr<Ptr<?>> freelist;

    public @Unsigned long tid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { void **freelist; long unsigned int tid; }; union { struct { void *freelist; long unsigned int counter; }; __int128 unsigned full; } freelist_tid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kmem_cache_cpu extends Union {
    public anon_member_of_anon_member_of_kmem_cache_cpu anon0;

    public freelist_aba_t freelist_tid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct hlist_node hlist_dup; struct list_head list; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_ksm_stable_node extends Struct {
    public hlist_node hlist_dup;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct list_head *head; struct { struct hlist_node hlist_dup; struct list_head list; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ksm_stable_node extends Struct {
    public Ptr<list_head> head;

    public anon_member_of_anon_member_of_anon_member_of_ksm_stable_node anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct rb_node node; struct { struct list_head *head; struct { struct hlist_node hlist_dup; struct list_head list; }; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ksm_stable_node extends Union {
    public rb_node node;

    public anon_member_of_anon_member_of_ksm_stable_node anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct anon_vma *anon_vma; int nid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ksm_rmap_item extends Union {
    public Ptr<anon_vma> anon_vma;

    public int nid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct ksm_stable_node *head; struct hlist_node hlist; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ksm_rmap_item extends Struct {
    public Ptr<ksm_stable_node> head;

    public hlist_node hlist;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct page *b_page; struct folio *b_folio; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_buffer_head extends Union {
    public Ptr<page> b_page;

    public Ptr<folio> b_folio;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct folio *folio; long unsigned int pfn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_folio_or_pfn extends Union {
    public Ptr<folio> folio;

    public @Unsigned long pfn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct __kfifo kfifo; struct memory_failure_entry *type; const struct memory_failure_entry *const_type; u8 (*rectype)[0]; struct memory_failure_entry *ptr; const struct memory_failure_entry *ptr_const; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fifo_of_memory_failure_cpu extends Union {
    public __kfifo kfifo;

    public Ptr<memory_failure_entry> type;

    public Ptr<memory_failure_entry> const_type;

    public Ptr<char @Size(0) []> rectype;

    public Ptr<memory_failure_entry> ptr;

    public Ptr<memory_failure_entry> ptr_const;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct zpdesc *next; long unsigned int handle; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_zpdesc extends Union {
    public Ptr<zpdesc> next;

    public @Unsigned long handle;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int next; long unsigned int handle; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_link_free extends Union {
    public @Unsigned long next;

    public @Unsigned long handle;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int huge; unsigned int fullness; unsigned int class; unsigned int magic; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_zspage extends Struct {
    public @Unsigned int huge;

    public @Unsigned int fullness;

    public @Unsigned int _class;

    public @Unsigned int magic;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int early_pfn; long unsigned int *bitmap; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_cma_memrange extends Union {
    public @Unsigned long early_pfn;

    public Ptr<java.lang. @Unsigned Long> bitmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct path user_path; struct { long unsigned int v; } bf_freeptr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_backing_file extends Union {
    public path user_path;

    public freeptr_t bf_freeptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct rb_root mounts; struct rb_node *mnt_last_node; struct rb_node *mnt_first_node; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mnt_namespace extends Struct {
    public rb_root mounts;

    public Ptr<rb_node> mnt_last_node;

    public Ptr<rb_node> mnt_first_node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct rb_node mnt_node; struct callback_head mnt_rcu; struct llist_node mnt_llist; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mount extends Union {
    public rb_node mnt_node;

    public callback_head mnt_rcu;

    public llist_node mnt_llist;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long int found; struct dentry *victim; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_select_data extends Union {
    public long found;

    public Ptr<dentry> victim;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const void *cvalue; void *value; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kernel_xattr_ctx extends Union {
    public Ptr<?> cvalue;

    public Ptr<?> value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const struct proc_ops *proc_ops; const struct file_operations *proc_dir_ops; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_proc_dir_entry extends Union {
    public Ptr<proc_ops> proc_ops;

    public Ptr<file_operations> proc_dir_ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct page* pages[64]; struct work_struct complete_work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dio extends Union {
    public Ptr<page> @Size(64) [] pages;

    public work_struct complete_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int type; unsigned int hash; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fanotify_event extends Struct {
    public @Unsigned int type;

    public @Unsigned int hash;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct fanotify_fh object_fh; u8 _inline_fh_buf[12]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fanotify_fid_event extends Struct {
    public fanotify_fh object_fh;

    public char @Size(12) [] _inline_fh_buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct fanotify_fh object_fh; u8 _inline_fh_buf[128]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fanotify_error_event extends Struct {
    public fanotify_fh object_fh;

    public char @Size(128) [] _inline_fh_buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct fanotify_response_info_header hdr; struct fanotify_response_info_audit_rule audit_rule; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fanotify_perm_event extends Union {
    public fanotify_response_info_header hdr;

    public fanotify_response_info_audit_rule audit_rule;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct rb_node rbn; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_epitem extends Union {
    public rb_node rbn;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { int counter; } reqs_available; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kioctx extends Struct {
    public atomic_t reqs_available;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct file *ki_filp; struct kiocb rw; struct fsync_iocb fsync; struct poll_iocb poll; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_aio_kiocb extends Union {
    public Ptr<file> ki_filp;

    public kiocb rw;

    public fsync_iocb fsync;

    public poll_iocb poll;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int index; u8 nonce[16]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fscrypt_iv extends Struct {
    public @Unsigned @OriginalName("__le64") long index;

    public char @Size(16) [] nonce;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int digestsize; unsigned int statesize; struct crypto_alg base; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_shash_alg extends Struct {
    public @Unsigned int digestsize;

    public @Unsigned int statesize;

    public crypto_alg base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int digestsize; unsigned int statesize; struct crypto_alg base; }; struct hash_alg_common halg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_shash_alg extends Union {
    public anon_member_of_anon_member_of_shash_alg anon0;

    public hash_alg_common halg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head rq_list; struct rb_node rq_recv; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_rpc_rqst extends Union {
    public list_head rq_list;

    public rb_node rq_recv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct rpc_xprt_iter cl_xpi; struct work_struct cl_work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_rpc_clnt extends Union {
    public rpc_xprt_iter cl_xpi;

    public work_struct cl_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int seqid; u8 other[12]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_nfs4_stateid_and_anon_member_of_nfs4_stateid_struct extends Struct {
    public @Unsigned @OriginalName("__be32") int seqid;

    public char @Size(12) [] other;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 data[16]; struct { unsigned int seqid; u8 other[12]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nfs4_stateid_and_anon_member_of_nfs4_stateid_struct extends Union {
    public char @Size(16) [] data;

    public anon_member_of_anon_member_of_nfs4_stateid_and_anon_member_of_nfs4_stateid_struct anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { const unsigned int *bitmask; unsigned int bitmask_store[3]; enum nfs3_stable_how stable; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_nfs_pgio_args extends Struct {
    public Ptr<java.lang. @Unsigned Integer> bitmask;

    public @Unsigned int @Size(3) [] bitmask_store;

    public nfs3_stable_how stable;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int replen; struct { const unsigned int *bitmask; unsigned int bitmask_store[3]; enum nfs3_stable_how stable; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nfs_pgio_args extends Union {
    public @Unsigned int replen;

    public anon_member_of_anon_member_of_nfs_pgio_args anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int replen; int eof; void *scratch; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_nfs_pgio_res extends Struct {
    public @Unsigned int replen;

    public int eof;

    public Ptr<?> scratch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int replen; int eof; void *scratch; }; struct { struct nfs_writeverf *verf; const struct nfs_server *server; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nfs_pgio_res extends Union {
    public anon_member_of_anon_member_of_nfs_pgio_res anon0;

    public anon_member_of_anon_member_of_nfs_pgio_res anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int (*dispatch)(struct svc_rqst*); struct { unsigned int lovers; unsigned int hivers; } mismatch; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_svc_process_info extends Union {
    public Ptr<?> dispatch;

    public mismatch_of_anon_member_of_svc_process_info mismatch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct iov_iter *iter; struct task_struct *waiter; } submit; struct { struct work_struct work; } aio; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iomap_dio extends Union {
    public submit_of_anon_member_of_iomap_dio submit;

    public aio_of_anon_member_of_iomap_dio aio;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct genradix_node* children[64]; u8 data[512]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_genradix_node extends Union {
    public Ptr<genradix_node> @Size(64) [] children;

    public char @Size(512) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct configfs_attribute *attr; struct configfs_bin_attribute *bin_attr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_configfs_buffer extends Union {
    public Ptr<configfs_attribute> attr;

    public Ptr<configfs_bin_attribute> bin_attr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { transaction_s *h_transaction; journal_s *h_journal; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_handle_t_and_anon_member_of_jbd2_journal_handle extends Union {
    public Ptr<@OriginalName("transaction_t") transaction_s> h_transaction;

    public Ptr<@OriginalName("journal_t") journal_s> h_journal;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head i_orphan; unsigned int i_orphan_idx; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ext4_inode_info extends Union {
    public list_head i_orphan;

    public @Unsigned int i_orphan_idx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void **buffer; struct page **page; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_squashfs_page_actor extends Union {
    public Ptr<Ptr<?>> buffer;

    public Ptr<Ptr<page>> page;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int fragment_block; int fragment_size; int fragment_offset; long long unsigned int block_list_start; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_squashfs_inode_info extends Struct {
    public @Unsigned long fragment_block;

    public int fragment_size;

    public int fragment_offset;

    public @Unsigned long block_list_start;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int fragment_block; int fragment_size; int fragment_offset; long long unsigned int block_list_start; }; struct { long long unsigned int dir_idx_start; int dir_idx_offset; int dir_idx_cnt; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_squashfs_inode_info extends Union {
    public anon_member_of_anon_member_of_squashfs_inode_info anon0;

    public anon_member_of_anon_member_of_squashfs_inode_info anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 drive_number; u8 state; u8 signature; u8 vol_id[4]; u8 vol_label[11]; u8 fs_type[8]; } fat16; struct { unsigned int length; short unsigned int flags; u8 version[2]; unsigned int root_cluster; short unsigned int info_sector; short unsigned int backup_boot; short unsigned int reserved2[6]; u8 drive_number; u8 state; u8 signature; u8 vol_id[4]; u8 vol_label[11]; u8 fs_type[8]; } fat32; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fat_boot_sector extends Union {
    public fat16_of_anon_member_of_fat_boot_sector fat16;

    public fat32_of_anon_member_of_fat_boot_sector fat32;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct list_head write_files; struct list_head queued_writes; int writectr; int iocachectr; wait_queue_head page_waitq; wait_queue_head direct_io_waitq; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_fuse_inode extends Struct {
    public list_head write_files;

    public list_head queued_writes;

    public int writectr;

    public int iocachectr;

    public @OriginalName("wait_queue_head_t") wait_queue_head page_waitq;

    public @OriginalName("wait_queue_head_t") wait_queue_head direct_io_waitq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct list_head write_files; struct list_head queued_writes; int writectr; int iocachectr; wait_queue_head page_waitq; wait_queue_head direct_io_waitq; }; struct { _Bool cached; long long int size; long long int pos; long long unsigned int version; struct timespec64 mtime; long long unsigned int iversion; spinlock lock; } rdc; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fuse_inode extends Union {
    public anon_member_of_anon_member_of_fuse_inode anon0;

    public rdc_of_anon_member_of_fuse_inode rdc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct fuse_read_in in; long long unsigned int attr_ver; } read; struct { struct fuse_write_in in; struct fuse_write_out out; _Bool folio_locked; } write; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fuse_io_args extends Union {
    public read_of_anon_member_of_fuse_io_args read;

    public write_of_anon_member_of_fuse_io_args write;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const void *raw; const struct file_operations *real_fops; const struct debugfs_short_fops *short_fops; struct vfsmount* (*automount)(struct dentry*, void*); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_debugfs_inode_info extends Union {
    public Ptr<?> raw;

    public Ptr<file_operations> real_fops;

    public Ptr<debugfs_short_fops> short_fops;

    public @OriginalName("debugfs_automount_t") Ptr<?> automount;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { refcount_struct active_users; struct completion active_users_drained; struct mutex cancellations_mtx; struct list_head cancellations; unsigned int methods; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_debugfs_fsdata extends Struct {
    public @OriginalName("refcount_t") refcount_struct active_users;

    public completion active_users_drained;

    public mutex cancellations_mtx;

    public list_head cancellations;

    public @Unsigned int methods;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int private; int priv; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_keyctl_dh_params extends Union {
    public int _private;

    public int priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ordinal; unsigned int return_code; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tpm_header extends Union {
    public @Unsigned @OriginalName("__be32") int ordinal;

    public @Unsigned @OriginalName("__be32") int return_code;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int rule_cnt; unsigned int rss_context; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_rxnfc extends Union {
    public @Unsigned int rule_cnt;

    public @Unsigned int rss_context;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { enum ethtool_link_ext_substate_autoneg autoneg; enum ethtool_link_ext_substate_link_training link_training; enum ethtool_link_ext_substate_link_logical_mismatch link_logical_mismatch; enum ethtool_link_ext_substate_bad_signal_integrity bad_signal_integrity; enum ethtool_link_ext_substate_cable_issue cable_issue; enum ethtool_link_ext_substate_module module; unsigned int __link_ext_substate; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_link_ext_state_info extends Union {
    public ethtool_link_ext_substate_autoneg autoneg;

    public ethtool_link_ext_substate_link_training link_training;

    public ethtool_link_ext_substate_link_logical_mismatch link_logical_mismatch;

    public ethtool_link_ext_substate_bad_signal_integrity bad_signal_integrity;

    public ethtool_link_ext_substate_cable_issue cable_issue;

    public ethtool_link_ext_substate_module module;

    public @Unsigned int __link_ext_substate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int FramesTransmittedOK; long long unsigned int SingleCollisionFrames; long long unsigned int MultipleCollisionFrames; long long unsigned int FramesReceivedOK; long long unsigned int FrameCheckSequenceErrors; long long unsigned int AlignmentErrors; long long unsigned int OctetsTransmittedOK; long long unsigned int FramesWithDeferredXmissions; long long unsigned int LateCollisions; long long unsigned int FramesAbortedDueToXSColls; long long unsigned int FramesLostDueToIntMACXmitError; long long unsigned int CarrierSenseErrors; long long unsigned int OctetsReceivedOK; long long unsigned int FramesLostDueToIntMACRcvError; long long unsigned int MulticastFramesXmittedOK; long long unsigned int BroadcastFramesXmittedOK; long long unsigned int FramesWithExcessiveDeferral; long long unsigned int MulticastFramesReceivedOK; long long unsigned int BroadcastFramesReceivedOK; long long unsigned int InRangeLengthErrors; long long unsigned int OutOfRangeLengthField; long long unsigned int FrameTooLongErrors; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ethtool_eth_mac_stats_and_stats_of_anon_member_of_ethtool_eth_mac_stats extends Struct {
    public @Unsigned long FramesTransmittedOK;

    public @Unsigned long SingleCollisionFrames;

    public @Unsigned long MultipleCollisionFrames;

    public @Unsigned long FramesReceivedOK;

    public @Unsigned long FrameCheckSequenceErrors;

    public @Unsigned long AlignmentErrors;

    public @Unsigned long OctetsTransmittedOK;

    public @Unsigned long FramesWithDeferredXmissions;

    public @Unsigned long LateCollisions;

    public @Unsigned long FramesAbortedDueToXSColls;

    public @Unsigned long FramesLostDueToIntMACXmitError;

    public @Unsigned long CarrierSenseErrors;

    public @Unsigned long OctetsReceivedOK;

    public @Unsigned long FramesLostDueToIntMACRcvError;

    public @Unsigned long MulticastFramesXmittedOK;

    public @Unsigned long BroadcastFramesXmittedOK;

    public @Unsigned long FramesWithExcessiveDeferral;

    public @Unsigned long MulticastFramesReceivedOK;

    public @Unsigned long BroadcastFramesReceivedOK;

    public @Unsigned long InRangeLengthErrors;

    public @Unsigned long OutOfRangeLengthField;

    public @Unsigned long FrameTooLongErrors;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int FramesTransmittedOK; long long unsigned int SingleCollisionFrames; long long unsigned int MultipleCollisionFrames; long long unsigned int FramesReceivedOK; long long unsigned int FrameCheckSequenceErrors; long long unsigned int AlignmentErrors; long long unsigned int OctetsTransmittedOK; long long unsigned int FramesWithDeferredXmissions; long long unsigned int LateCollisions; long long unsigned int FramesAbortedDueToXSColls; long long unsigned int FramesLostDueToIntMACXmitError; long long unsigned int CarrierSenseErrors; long long unsigned int OctetsReceivedOK; long long unsigned int FramesLostDueToIntMACRcvError; long long unsigned int MulticastFramesXmittedOK; long long unsigned int BroadcastFramesXmittedOK; long long unsigned int FramesWithExcessiveDeferral; long long unsigned int MulticastFramesReceivedOK; long long unsigned int BroadcastFramesReceivedOK; long long unsigned int InRangeLengthErrors; long long unsigned int OutOfRangeLengthField; long long unsigned int FrameTooLongErrors; }; struct { long long unsigned int FramesTransmittedOK; long long unsigned int SingleCollisionFrames; long long unsigned int MultipleCollisionFrames; long long unsigned int FramesReceivedOK; long long unsigned int FrameCheckSequenceErrors; long long unsigned int AlignmentErrors; long long unsigned int OctetsTransmittedOK; long long unsigned int FramesWithDeferredXmissions; long long unsigned int LateCollisions; long long unsigned int FramesAbortedDueToXSColls; long long unsigned int FramesLostDueToIntMACXmitError; long long unsigned int CarrierSenseErrors; long long unsigned int OctetsReceivedOK; long long unsigned int FramesLostDueToIntMACRcvError; long long unsigned int MulticastFramesXmittedOK; long long unsigned int BroadcastFramesXmittedOK; long long unsigned int FramesWithExcessiveDeferral; long long unsigned int MulticastFramesReceivedOK; long long unsigned int BroadcastFramesReceivedOK; long long unsigned int InRangeLengthErrors; long long unsigned int OutOfRangeLengthField; long long unsigned int FrameTooLongErrors; } stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_eth_mac_stats extends Union {
    public anon_member_of_anon_member_of_ethtool_eth_mac_stats_and_stats_of_anon_member_of_ethtool_eth_mac_stats anon0;

    public anon_member_of_anon_member_of_ethtool_eth_mac_stats_and_stats_of_anon_member_of_ethtool_eth_mac_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int SymbolErrorDuringCarrier; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ethtool_eth_phy_stats_and_stats_of_anon_member_of_ethtool_eth_phy_stats extends Struct {
    public @Unsigned long SymbolErrorDuringCarrier;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int SymbolErrorDuringCarrier; }; struct { long long unsigned int SymbolErrorDuringCarrier; } stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_eth_phy_stats extends Union {
    public anon_member_of_anon_member_of_ethtool_eth_phy_stats_and_stats_of_anon_member_of_ethtool_eth_phy_stats anon0;

    public anon_member_of_anon_member_of_ethtool_eth_phy_stats_and_stats_of_anon_member_of_ethtool_eth_phy_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int MACControlFramesTransmitted; long long unsigned int MACControlFramesReceived; long long unsigned int UnsupportedOpcodesReceived; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ethtool_eth_ctrl_stats_and_stats_of_anon_member_of_ethtool_eth_ctrl_stats extends Struct {
    public @Unsigned long MACControlFramesTransmitted;

    public @Unsigned long MACControlFramesReceived;

    public @Unsigned long UnsupportedOpcodesReceived;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int MACControlFramesTransmitted; long long unsigned int MACControlFramesReceived; long long unsigned int UnsupportedOpcodesReceived; }; struct { long long unsigned int MACControlFramesTransmitted; long long unsigned int MACControlFramesReceived; long long unsigned int UnsupportedOpcodesReceived; } stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_eth_ctrl_stats extends Union {
    public anon_member_of_anon_member_of_ethtool_eth_ctrl_stats_and_stats_of_anon_member_of_ethtool_eth_ctrl_stats anon0;

    public anon_member_of_anon_member_of_ethtool_eth_ctrl_stats_and_stats_of_anon_member_of_ethtool_eth_ctrl_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int tx_pause_frames; long long unsigned int rx_pause_frames; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ethtool_pause_stats_and_stats_of_anon_member_of_ethtool_pause_stats extends Struct {
    public @Unsigned long tx_pause_frames;

    public @Unsigned long rx_pause_frames;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int tx_pause_frames; long long unsigned int rx_pause_frames; }; struct { long long unsigned int tx_pause_frames; long long unsigned int rx_pause_frames; } stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_pause_stats extends Union {
    public anon_member_of_anon_member_of_ethtool_pause_stats_and_stats_of_anon_member_of_ethtool_pause_stats anon0;

    public anon_member_of_anon_member_of_ethtool_pause_stats_and_stats_of_anon_member_of_ethtool_pause_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int undersize_pkts; long long unsigned int oversize_pkts; long long unsigned int fragments; long long unsigned int jabbers; long long unsigned int hist[11]; long long unsigned int hist_tx[11]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ethtool_rmon_stats_and_stats_of_anon_member_of_ethtool_rmon_stats extends Struct {
    public @Unsigned long undersize_pkts;

    public @Unsigned long oversize_pkts;

    public @Unsigned long fragments;

    public @Unsigned long jabbers;

    public @Unsigned long @Size(11) [] hist;

    public @Unsigned long @Size(11) [] hist_tx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int undersize_pkts; long long unsigned int oversize_pkts; long long unsigned int fragments; long long unsigned int jabbers; long long unsigned int hist[11]; long long unsigned int hist_tx[11]; }; struct { long long unsigned int undersize_pkts; long long unsigned int oversize_pkts; long long unsigned int fragments; long long unsigned int jabbers; long long unsigned int hist[11]; long long unsigned int hist_tx[11]; } stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_rmon_stats extends Union {
    public anon_member_of_anon_member_of_ethtool_rmon_stats_and_stats_of_anon_member_of_ethtool_rmon_stats anon0;

    public anon_member_of_anon_member_of_ethtool_rmon_stats_and_stats_of_anon_member_of_ethtool_rmon_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int pkts; long long unsigned int onestep_pkts_unconfirmed; long long unsigned int lost; long long unsigned int err; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ethtool_ts_stats_and_tx_stats_of_anon_member_of_ethtool_ts_stats extends Struct {
    public @Unsigned long pkts;

    public @Unsigned long onestep_pkts_unconfirmed;

    public @Unsigned long lost;

    public @Unsigned long err;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int pkts; long long unsigned int onestep_pkts_unconfirmed; long long unsigned int lost; long long unsigned int err; }; struct { long long unsigned int pkts; long long unsigned int onestep_pkts_unconfirmed; long long unsigned int lost; long long unsigned int err; } tx_stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_ts_stats extends Union {
    public anon_member_of_anon_member_of_ethtool_ts_stats_and_tx_stats_of_anon_member_of_ethtool_ts_stats anon0;

    public anon_member_of_anon_member_of_ethtool_ts_stats_and_tx_stats_of_anon_member_of_ethtool_ts_stats tx_stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct smack_audit_data *smack_audit_data; struct selinux_audit_data *selinux_audit_data; struct apparmor_audit_data *apparmor_audit_data; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_common_audit_data extends Union {
    public Ptr<smack_audit_data> smack_audit_data;

    public Ptr<selinux_audit_data> selinux_audit_data;

    public Ptr<apparmor_audit_data> apparmor_audit_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int saddr; unsigned int daddr; }; struct { unsigned int saddr; unsigned int daddr; } addrs; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iphdr extends Union {
    public addrs_of_anon_member_of_iphdr_and_anon_member_of_anon_member_of_iphdr_and_v4_of_bpf_sk_lookup_kern anon0;

    public addrs_of_anon_member_of_iphdr_and_anon_member_of_anon_member_of_iphdr_and_v4_of_bpf_sk_lookup_kern addrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct in6_addr saddr; struct in6_addr daddr; }; struct { struct in6_addr saddr; struct in6_addr daddr; } addrs; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ipv6hdr extends Union {
    public addrs_of_anon_member_of_ipv6hdr_and_anon_member_of_anon_member_of_ipv6hdr anon0;

    public addrs_of_anon_member_of_ipv6hdr_and_anon_member_of_anon_member_of_ipv6hdr addrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 reserved; u8 preferpd; u8 routeraddr; u8 autoconf; u8 onlink; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_prefix_info extends Struct {
    public char reserved;

    public char preferpd;

    public char routeraddr;

    public char autoconf;

    public char onlink;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 flags; struct { u8 reserved; u8 preferpd; u8 routeraddr; u8 autoconf; u8 onlink; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_prefix_info extends Union {
    public char flags;

    public anon_member_of_anon_member_of_prefix_info anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ppid; unsigned int fsn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sctp_idatahdr extends Union {
    public @Unsigned int ppid;

    public @Unsigned @OriginalName("__be32") int fsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int mid; short unsigned int ssn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sctp_stream_in_and_anon_member_of_sctp_stream_out_and_anon_member_of_sctp_ulpevent extends Union {
    public @Unsigned int mid;

    public @Unsigned short ssn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ppid; unsigned int fsn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sctp_ulpevent extends Union {
    public @Unsigned int ppid;

    public @Unsigned int fsn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head transmitted_list; struct list_head stream_list; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sctp_chunk extends Union {
    public list_head transmitted_list;

    public list_head stream_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct list_head prio_list; struct sctp_stream_priorities *prio_head; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_sctp_stream_out_ext extends Struct {
    public list_head prio_list;

    public Ptr<sctp_stream_priorities> prio_head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct list_head prio_list; struct sctp_stream_priorities *prio_head; }; struct { struct list_head rr_list; }; struct { struct list_head fc_list; unsigned int fc_length; short unsigned int fc_weight; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sctp_stream_out_ext extends Union {
    public anon_member_of_anon_member_of_sctp_stream_out_ext anon0;

    public anon_member_of_anon_member_of_sctp_stream_out_ext anon1;

    public anon_member_of_anon_member_of_sctp_stream_out_ext anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct list_head prio_list; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_sctp_stream extends Struct {
    public list_head prio_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct list_head prio_list; }; struct { struct list_head rr_list; struct sctp_stream_out_ext *rr_next; }; struct { struct list_head fc_list; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sctp_stream extends Union {
    public anon_member_of_anon_member_of_sctp_stream anon0;

    public anon_member_of_anon_member_of_sctp_stream anon1;

    public anon_member_of_anon_member_of_sctp_stream anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct apparmor_notif base; struct apparmor_notif_resp_perm perm; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_apparmor_notif_resp_name extends Union {
    public apparmor_notif base;

    public apparmor_notif_resp_perm perm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct apparmor_notif_common base; unsigned int modeset; unsigned int ns; unsigned int filter; u8 data[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_apparmor_notif_filters extends Struct {
    public apparmor_notif_common base;

    public @Unsigned int modeset;

    public @Unsigned int ns;

    public @Unsigned int filter;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_rules; struct aa_ruleset* rules[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_aa_label extends Struct {
    public lockdep_map_p __empty_rules;

    public Ptr<aa_ruleset> @Size(0) [] rules;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct aa_profile* profile[2]; struct { struct { } __empty_rules; struct aa_ruleset* rules[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_aa_label extends Struct {
    public Ptr<aa_profile> @Size(2) [] profile;

    public anon_member_of_anon_member_of_anon_member_of_aa_label anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct aa_profile* profile[2]; struct { struct { } __empty_rules; struct aa_ruleset* rules[0]; }; }; struct { struct { } __empty_vec; struct aa_profile* vec[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_aa_label extends Union {
    public anon_member_of_anon_member_of_aa_label anon0;

    public anon_member_of_anon_member_of_aa_label anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { int signal; int unmappedsig; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data extends Struct {
    public int signal;

    public int unmappedsig;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { const u8 *target; struct { unsigned int val; } ouid; } fs; struct { int rlim; long unsigned int max; } rlim; struct { int signal; int unmappedsig; }; struct { int type; int protocol; void *addr; int addrlen; struct { void *addr; int addrlen; } peer; } net; struct { const u8 *target; } ns; struct { struct { unsigned int val; } ouid; } mq; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data extends Union {
    public fs_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data fs;

    public rlim_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data rlim;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data anon2;

    public net_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data net;

    public ns_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data ns;

    public mq_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data mq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct aa_label *peer; union { struct { const u8 *target; struct { unsigned int val; } ouid; } fs; struct { int rlim; long unsigned int max; } rlim; struct { int signal; int unmappedsig; }; struct { int type; int protocol; void *addr; int addrlen; struct { void *addr; int addrlen; } peer; } net; struct { const u8 *target; } ns; struct { struct { unsigned int val; } ouid; } mq; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_apparmor_audit_data extends Struct {
    public Ptr<aa_label> peer;

    @InlineUnion(28665)
    public fs_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data fs;

    @InlineUnion(28665)
    public rlim_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data rlim;

    @InlineUnion(28665)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data anon1$2;

    @InlineUnion(28665)
    public net_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data net;

    @InlineUnion(28665)
    public ns_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data ns;

    @InlineUnion(28665)
    public mq_of_anon_member_of_anon_member_of_anon_member_of_apparmor_audit_data mq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct aa_label *peer; union { struct { const u8 *target; struct { unsigned int val; } ouid; } fs; struct { int rlim; long unsigned int max; } rlim; struct { int signal; int unmappedsig; }; struct { int type; int protocol; void *addr; int addrlen; struct { void *addr; int addrlen; } peer; } net; struct { const u8 *target; } ns; struct { struct { unsigned int val; } ouid; } mq; }; }; struct { struct aa_profile *profile; const u8 *ns; long int pos; } iface; struct { const u8 *src_name; const u8 *type; const u8 *trans; const u8 *data; long unsigned int flags; } mnt; struct { struct aa_label *target; } uring; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_apparmor_audit_data extends Union {
    public anon_member_of_anon_member_of_apparmor_audit_data anon0;

    public iface_of_anon_member_of_apparmor_audit_data iface;

    public mnt_of_anon_member_of_apparmor_audit_data mnt;

    public uring_of_anon_member_of_apparmor_audit_data uring;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct aa_perms *perms; unsigned int size; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_aa_policydb extends Struct {
    public Ptr<aa_perms> perms;

    public @Unsigned int size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_buffer; u8 buffer[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_aa_buffer extends Struct {
    public lockdep_map_p __empty_buffer;

    public char @Size(0) [] buffer;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct sockaddr addr; struct sockaddr_in addr4; struct sockaddr_in6 addr6; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_stored_match_addr extends Union {
    public sockaddr addr;

    public sockaddr_in addr4;

    public sockaddr_in6 addr6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct apparmor_notif_op base; unsigned int subj_uid; unsigned int obj_uid; unsigned int name; u8 data[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_apparmor_notif_recv extends Struct {
    public apparmor_notif_op base;

    public @Unsigned @OriginalName("uid_t") int subj_uid;

    public @Unsigned @OriginalName("uid_t") int obj_uid;

    public @Unsigned int name;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct mutex lock; refcount_struct usage; unsigned int num_rules; unsigned int num_layers; struct access_masks access_masks[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_landlock_ruleset extends Struct {
    public mutex lock;

    public @OriginalName("refcount_t") refcount_struct usage;

    public @Unsigned int num_rules;

    public @Unsigned int num_layers;

    public access_masks @Size(0) [] access_masks;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct work_struct work_free; struct { struct mutex lock; refcount_struct usage; unsigned int num_rules; unsigned int num_layers; struct access_masks access_masks[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_landlock_ruleset extends Union {
    public work_struct work_free;

    public anon_member_of_anon_member_of_landlock_ruleset anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct callback_head rcu_free; const struct landlock_object_underops *underops; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_landlock_object extends Union {
    public callback_head rcu_free;

    public Ptr<landlock_object_underops> underops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_evm_ima_xattr_data extends Struct {
    public char type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 type; }; struct evm_ima_xattr_data_hdr hdr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_evm_ima_xattr_data extends Union {
    public anon_member_of_anon_member_of_evm_ima_xattr_data anon0;

    public evm_ima_xattr_data_hdr hdr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 algo; u8 length; union { struct { u8 unused; u8 type; } sha1; struct { u8 type; u8 algo; } ng; u8 data[2]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ima_digest_data extends Struct {
    public char algo;

    public char length;

    public xattr_of_anon_member_of_anon_member_of_ima_digest_data_and_xattr_of_ima_digest_data_hdr xattr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 algo; u8 length; union { struct { u8 unused; u8 type; } sha1; struct { u8 type; u8 algo; } ng; u8 data[2]; }; }; struct ima_digest_data_hdr hdr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ima_digest_data extends Union {
    public anon_member_of_anon_member_of_ima_digest_data anon0;

    public ima_digest_data_hdr hdr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct hlist_node list; struct crypto_spawn *spawns; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_crypto_instance extends Union {
    public hlist_node list;

    public Ptr<crypto_spawn> spawns;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct crypto_instance *inst; struct crypto_spawn *next; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_crypto_spawn extends Union {
    public Ptr<crypto_instance> inst;

    public Ptr<crypto_spawn> next;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const void* addr; crypto_no_such_thing *__addr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_scatter_walk extends Union {
    public Ptr<?> addr;

    public @OriginalName("crypto_no_such_thing") Ptr<?> __addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { const const void* addr; } virt; } src; struct scatter_walk in; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acomp_walk_and_anon_member_of_skcipher_walk extends Union {
    public src_of_anon_member_of_acomp_walk_and_anon_member_of_skcipher_walk src;

    public scatter_walk in;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 head[64]; struct crypto_instance base; } s; struct aead_alg alg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_aead_instance extends Union {
    public s_of_anon_member_of_aead_instance_and_s_of_anon_member_of_lskcipher_instance s;

    public aead_alg alg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 head[64]; struct crypto_instance base; } s; struct lskcipher_alg alg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_lskcipher_instance extends Union {
    public s_of_anon_member_of_aead_instance_and_s_of_anon_member_of_lskcipher_instance s;

    public lskcipher_alg alg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int min_keysize; unsigned int max_keysize; unsigned int ivsize; unsigned int chunksize; unsigned int statesize; struct crypto_alg base; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_skcipher_alg extends Struct {
    public @Unsigned int min_keysize;

    public @Unsigned int max_keysize;

    public @Unsigned int ivsize;

    public @Unsigned int chunksize;

    public @Unsigned int statesize;

    public crypto_alg base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int min_keysize; unsigned int max_keysize; unsigned int ivsize; unsigned int chunksize; unsigned int statesize; struct crypto_alg base; }; struct skcipher_alg_common co; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_skcipher_alg extends Union {
    public anon_member_of_anon_member_of_skcipher_alg anon0;

    public skcipher_alg_common co;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 head[88]; struct crypto_instance base; } s; struct skcipher_alg alg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_skcipher_instance extends Union {
    public s_of_anon_member_of_skcipher_instance s;

    public skcipher_alg alg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 head[112]; struct crypto_instance base; } s; struct ahash_alg alg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ahash_instance extends Union {
    public s_of_anon_member_of_ahash_instance s;

    public ahash_alg alg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 head[120]; struct crypto_instance base; } s; struct shash_alg alg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_shash_instance extends Union {
    public s_of_anon_member_of_shash_instance s;

    public shash_alg alg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 head[56]; struct crypto_instance base; } s; struct akcipher_alg alg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_akcipher_instance extends Union {
    public s_of_anon_member_of_akcipher_instance s;

    public akcipher_alg alg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 head[72]; struct crypto_instance base; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_sig_instance extends Struct {
    public char @Size(72) [] head;

    public crypto_instance base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 head[72]; struct crypto_instance base; }; struct sig_alg alg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sig_instance extends Union {
    public anon_member_of_anon_member_of_sig_instance anon0;

    public sig_alg alg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 head[48]; struct crypto_instance base; } s; struct kpp_alg alg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_kpp_instance extends Union {
    public s_of_anon_member_of_kpp_instance s;

    public kpp_alg alg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct crypto_alg base; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_acomp_alg_and_anon_member_of_scomp_alg extends Struct {
    public crypto_alg base;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct crypto_alg base; }; struct comp_alg_common calg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acomp_alg_and_anon_member_of_scomp_alg extends Union {
    public anon_member_of_anon_member_of_acomp_alg_and_anon_member_of_scomp_alg anon0;

    public comp_alg_common calg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *src; long unsigned int saddr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_scomp_scratch extends Union {
    public Ptr<?> src;

    public @Unsigned long saddr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct kiocb *iocb; struct task_struct *waiter; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_blkdev_dio extends Union {
    public Ptr<kiocb> iocb;

    public Ptr<task_struct> waiter;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct work_struct async_bio_work; struct work_struct free_work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_blkcg_gq extends Union {
    public work_struct async_bio_work;

    public work_struct free_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { spinlock lock; struct list_head rq_lists[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_blk_mq_ctx extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public list_head @Size(3) [] rq_lists;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct work_struct work; struct bio *bio; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bio_fallback_crypt_ctx extends Struct {
    public work_struct work;

    public Ptr<bio> bio;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct work_struct work; struct bio *bio; }; struct { void *bi_private_orig; void (*bi_end_io_orig)(struct bio*); }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bio_fallback_crypt_ctx extends Union {
    public anon_member_of_anon_member_of_bio_fallback_crypt_ctx anon0;

    public anon_member_of_anon_member_of_bio_fallback_crypt_ctx anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int resv1; unsigned int resv2; short unsigned int resv3; short unsigned int tail; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_io_uring_buf_ring extends Struct {
    public @Unsigned long resv1;

    public @Unsigned int resv2;

    public @Unsigned short resv3;

    public @Unsigned short tail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int resv1; unsigned int resv2; short unsigned int resv3; short unsigned int tail; }; struct { struct { } __empty_bufs; struct io_uring_buf bufs[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_uring_buf_ring extends Union {
    public anon_member_of_anon_member_of_io_uring_buf_ring anon0;

    public anon_member_of_anon_member_of_io_uring_buf_ring anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int file_ptr; struct io_mapped_ubuf *buf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_rsrc_node extends Union {
    public @Unsigned long file_ptr;

    public Ptr<io_mapped_ubuf> buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct list_head buf_list; struct io_uring_buf_ring *buf_ring; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_buffer_list extends Union {
    public list_head buf_list;

    public Ptr<io_uring_buf_ring> buf_ring;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct iovec *iovec; struct bio_vec *bvec; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iou_vec extends Union {
    public Ptr<iovec> iovec;

    public Ptr<bio_vec> bvec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct uio_meta meta; struct io_meta_state meta_state; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_io_async_rw_and_clear_of_anon_member_of_io_async_rw extends Struct {
    public uio_meta meta;

    public io_meta_state meta_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct wait_page_queue wpq; struct { struct uio_meta meta; struct io_meta_state meta_state; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_io_async_rw_and_clear_of_anon_member_of_io_async_rw extends Union {
    public wait_page_queue wpq;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_io_async_rw_and_clear_of_anon_member_of_io_async_rw anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct iov_iter iter; struct iov_iter_state iter_state; struct iovec fast_iov; unsigned int buf_group; union { struct wait_page_queue wpq; struct { struct uio_meta meta; struct io_meta_state meta_state; }; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_io_async_rw_and_clear_of_anon_member_of_io_async_rw extends Struct {
    public iov_iter iter;

    public iov_iter_state iter_state;

    public iovec fast_iov;

    public @Unsigned int buf_group;

    @InlineUnion(31951)
    public wait_page_queue wpq;

    @InlineUnion(31951)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_io_async_rw_and_clear_of_anon_member_of_io_async_rw anon4$1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct iov_iter iter; struct iov_iter_state iter_state; struct iovec fast_iov; unsigned int buf_group; union { struct wait_page_queue wpq; struct { struct uio_meta meta; struct io_meta_state meta_state; }; }; }; struct { struct iov_iter iter; struct iov_iter_state iter_state; struct iovec fast_iov; unsigned int buf_group; union { struct wait_page_queue wpq; struct { struct uio_meta meta; struct io_meta_state meta_state; }; }; } clear; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_async_rw extends Union {
    public anon_member_of_anon_member_of_io_async_rw_and_clear_of_anon_member_of_io_async_rw anon0;

    public anon_member_of_anon_member_of_io_async_rw_and_clear_of_anon_member_of_io_async_rw clear;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int data; struct file *file; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_cancel_data extends Union {
    public @Unsigned long data;

    public Ptr<file> file;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int dst_fd; unsigned int cqe_flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_msg extends Union {
    public @Unsigned int dst_fd;

    public @Unsigned int cqe_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 register_op; u8 sqe_op; u8 sqe_flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_uring_restriction extends Union {
    public char register_op;

    public char sqe_op;

    public char sqe_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int _flags; long unsigned int pp_magic; struct page_pool *pp; long unsigned int _pp_mapping_pad; long unsigned int dma_addr; struct { long long int counter; } pp_ref_count; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_net_iov extends Struct {
    public @Unsigned long _flags;

    public @Unsigned long pp_magic;

    public Ptr<page_pool> pp;

    public @Unsigned long _pp_mapping_pad;

    public @Unsigned long dma_addr;

    public @OriginalName("atomic_long_t") atomic64_t pp_ref_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct netmem_desc desc; struct { long unsigned int _flags; long unsigned int pp_magic; struct page_pool *pp; long unsigned int _pp_mapping_pad; long unsigned int dma_addr; struct { long long int counter; } pp_ref_count; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_net_iov extends Union {
    public netmem_desc desc;

    public anon_member_of_anon_member_of_net_iov anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct callback_head rcu; struct delayed_work work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_worker extends Union {
    public callback_head rcu;

    public delayed_work work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { int namelen; struct iovec fast_iov; long unsigned int controllen; long unsigned int payloadlen; struct sockaddr *uaddr; struct msghdr msg; struct __kernel_sockaddr_storage addr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_io_async_msghdr_and_clear_of_anon_member_of_io_async_msghdr extends Struct {
    public int namelen;

    public iovec fast_iov;

    public @Unsigned @OriginalName("__kernel_size_t") long controllen;

    public @Unsigned @OriginalName("__kernel_size_t") long payloadlen;

    public Ptr<sockaddr> uaddr;

    public msghdr msg;

    public __kernel_sockaddr_storage addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { int namelen; struct iovec fast_iov; long unsigned int controllen; long unsigned int payloadlen; struct sockaddr *uaddr; struct msghdr msg; struct __kernel_sockaddr_storage addr; }; struct { int namelen; struct iovec fast_iov; long unsigned int controllen; long unsigned int payloadlen; struct sockaddr *uaddr; struct msghdr msg; struct __kernel_sockaddr_storage addr; } clear; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_async_msghdr extends Union {
    public anon_member_of_anon_member_of_io_async_msghdr_and_clear_of_anon_member_of_io_async_msghdr anon0;

    public anon_member_of_anon_member_of_io_async_msghdr_and_clear_of_anon_member_of_io_async_msghdr clear;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct compat_msghdr *umsg_compat; struct user_msghdr *umsg; void *buf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_sr_msg extends Union {
    public Ptr<compat_msghdr> umsg_compat;

    public Ptr<user_msghdr> umsg;

    public Ptr<?> buf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ee_data; struct sock_ee_data_rfc4884 ee_rfc4884; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sock_extended_err extends Union {
    public @Unsigned int ee_data;

    public sock_ee_data_rfc4884 ee_rfc4884;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct inet_skb_parm h4; struct inet6_skb_parm h6; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ipfrag_skb_cb_and_header_of_anon_member_of_tcp_skb_cb_and_header_of_sock_exterr_skb extends Union {
    public inet_skb_parm h4;

    public inet6_skb_parm h6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int r[5]; long long unsigned int r64[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_poly1305_key extends Union {
    public @Unsigned int @Size(5) [] r;

    public @Unsigned long @Size(3) [] r64;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int h[5]; long long unsigned int h64[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_poly1305_state extends Union {
    public @Unsigned int @Size(5) [] h;

    public @Unsigned long @Size(3) [] h64;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct poly1305_key opaque_r[11]; struct poly1305_core_key core_r; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_poly1305_block_state extends Union {
    public poly1305_key @Size(11) [] opaque_r;

    public poly1305_core_key core_r;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int h[5]; unsigned int is_base2_26; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_poly1305_arch_internal extends Struct {
    public @Unsigned int @Size(5) [] h;

    public @Unsigned int is_base2_26;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int h[5]; unsigned int is_base2_26; }; long long unsigned int hs[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_poly1305_arch_internal extends Union {
    public anon_member_of_anon_member_of_poly1305_arch_internal anon0;

    public @Unsigned long @Size(3) [] hs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int start_hole; long unsigned int start_used; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_interval_tree_span_iter extends Union {
    public @Unsigned long start_hole;

    public @Unsigned long start_used;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int *bits; unsigned int *lvl; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ddebug_class_param extends Union {
    public Ptr<java.lang. @Unsigned Long> bits;

    public Ptr<java.lang. @Unsigned Integer> lvl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ib_ah_attr ib; struct roce_ah_attr roce; struct opa_ah_attr opa; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_rdma_ah_attr extends Union {
    public ib_ah_attr ib;

    public roce_ah_attr roce;

    public opa_ah_attr opa;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int wr_id; struct ib_cqe *wr_cqe; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ib_recv_wr_and_anon_member_of_ib_send_wr_and_anon_member_of_ib_wc extends Union {
    public @Unsigned long wr_id;

    public Ptr<ib_cqe> wr_cqe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct ib_xrcd *xrcd; } xrc; struct { unsigned int max_num_tags; } tag_matching; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ext_of_ib_srq_init_attr extends Union {
    public xrc_of_anon_member_of_ext_of_ib_srq_init_attr xrc;

    public tag_matching_of_anon_member_of_ext_of_ib_srq_init_attr tag_matching;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct irq_poll iop; struct work_struct work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ib_cq extends Union {
    public irq_poll iop;

    public work_struct work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct ib_xrcd *xrcd; unsigned int srq_num; } xrc; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ext_of_ib_srq extends Union {
    public xrc_of_anon_member_of_ext_of_ib_srq xrc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ib_uobject *uobject; struct list_head qp_entry; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ib_mr extends Union {
    public Ptr<ib_uobject> uobject;

    public list_head qp_entry;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int type; short unsigned int size; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ib_flow_spec extends Struct {
    public @Unsigned int type;

    public @Unsigned short size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct device dev; struct ib_core_device coredev; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ib_device extends Union {
    public device dev;

    public ib_core_device coredev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct workqueue_struct *wq; struct closure_syncer *s; struct llist_node list; void (*fn)(struct work_struct*); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_closure extends Struct {
    public Ptr<workqueue_struct> wq;

    public Ptr<closure_syncer> s;

    public llist_node list;

    public Ptr<?> fn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct workqueue_struct *wq; struct closure_syncer *s; struct llist_node list; void (*fn)(struct work_struct*); }; struct work_struct work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_closure extends Union {
    public anon_member_of_anon_member_of_closure anon0;

    public work_struct work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int pool_index_plus_1; unsigned int offset; unsigned int extra; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_handle_parts extends Struct {
    public @Unsigned int pool_index_plus_1;

    public @Unsigned int offset;

    public @Unsigned int extra;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct list_head free_list; long unsigned int rcu_state; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_stack_record extends Struct {
    public list_head free_list;

    public @Unsigned long rcu_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int entries[64]; struct { struct list_head free_list; long unsigned int rcu_state; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_stack_record extends Union {
    public @Unsigned long @Size(64) [] entries;

    public anon_member_of_anon_member_of_stack_record anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int line; unsigned int column; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_source_location extends Struct {
    public @Unsigned int line;

    public @Unsigned int column;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int reported; struct { unsigned int line; unsigned int column; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_source_location extends Union {
    public @Unsigned long reported;

    public anon_member_of_anon_member_of_source_location anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ngroups; unsigned int ncpus; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_node_groups extends Union {
    public @Unsigned int ngroups;

    public @Unsigned int ncpus;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int l; unsigned int h; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_msr extends Struct {
    public @Unsigned int l;

    public @Unsigned int h;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int l; unsigned int h; }; long long unsigned int q; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_msr extends Union {
    public anon_member_of_anon_member_of_msr anon0;

    public @Unsigned long q;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *parent_handler_data; void **parent_handler_data_array; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_gpio_irq_chip extends Union {
    public Ptr<?> parent_handler_data;

    public Ptr<Ptr<?>> parent_handler_data_array;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int (*xfer)(struct i2c_adapter*, struct i2c_msg*, int); int (*master_xfer)(struct i2c_adapter*, struct i2c_msg*, int); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_i2c_algorithm extends Union {
    public Ptr<?> xfer;

    public Ptr<?> master_xfer;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int flags; long long unsigned int values; unsigned int debounce_period_us; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_gpio_v2_line_attribute extends Union {
    public @Unsigned long flags;

    public @Unsigned long values;

    public @Unsigned int debounce_period_us;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct __kfifo kfifo; struct gpio_v2_line_event *type; const struct gpio_v2_line_event *const_type; u8 (*rectype)[0]; struct gpio_v2_line_event *ptr; const struct gpio_v2_line_event *ptr_const; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_events_of_linereq extends Union {
    public __kfifo kfifo;

    public Ptr<gpio_v2_line_event> type;

    public Ptr<gpio_v2_line_event> const_type;

    public Ptr<char @Size(0) []> rectype;

    public Ptr<gpio_v2_line_event> ptr;

    public Ptr<gpio_v2_line_event> ptr_const;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct __kfifo kfifo; struct gpioevent_data *type; const struct gpioevent_data *const_type; u8 (*rectype)[0]; struct gpioevent_data *ptr; const struct gpioevent_data *ptr_const; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_events_of_lineevent_state extends Union {
    public __kfifo kfifo;

    public Ptr<gpioevent_data> type;

    public Ptr<gpioevent_data> const_type;

    public Ptr<char @Size(0) []> rectype;

    public Ptr<gpioevent_data> ptr;

    public Ptr<gpioevent_data> ptr_const;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct __kfifo kfifo; struct gpio_v2_line_info_changed *type; const struct gpio_v2_line_info_changed *const_type; u8 (*rectype)[0]; struct gpio_v2_line_info_changed *ptr; const struct gpio_v2_line_info_changed *ptr_const; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_events_of_gpio_chardev_data extends Union {
    public __kfifo kfifo;

    public Ptr<gpio_v2_line_info_changed> type;

    public Ptr<gpio_v2_line_info_changed> const_type;

    public Ptr<char @Size(0) []> rectype;

    public Ptr<gpio_v2_line_info_changed> ptr;

    public Ptr<gpio_v2_line_info_changed> ptr_const;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __Empty_interrupts; u8 interrupts[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_acpi_resource_irq extends Struct {
    public lockdep_map_p __Empty_interrupts;

    public char @Size(0) [] interrupts;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 interrupt; struct { struct { } __Empty_interrupts; u8 interrupts[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acpi_resource_irq extends Union {
    public char interrupt;

    public anon_member_of_anon_member_of_acpi_resource_irq anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __Empty_channels; u8 channels[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_acpi_resource_dma extends Struct {
    public lockdep_map_p __Empty_channels;

    public char @Size(0) [] channels;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 channel; struct { struct { } __Empty_channels; u8 channels[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acpi_resource_dma extends Union {
    public char channel;

    public anon_member_of_anon_member_of_acpi_resource_dma anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __Empty_interrupts; unsigned int interrupts[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_acpi_resource_extended_irq_and_anon_member_of_aml_resource_extended_irq extends Struct {
    public lockdep_map_p __Empty_interrupts;

    public @Unsigned int @Size(0) [] interrupts;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int interrupt; struct { struct { } __Empty_interrupts; unsigned int interrupts[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acpi_resource_extended_irq_and_anon_member_of_aml_resource_extended_irq extends Union {
    public @Unsigned int interrupt;

    public anon_member_of_anon_member_of_acpi_resource_extended_irq_and_anon_member_of_aml_resource_extended_irq anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct mutex nonatomic_lock; spinlock atomic_lock; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pwm_chip extends Union {
    public mutex nonatomic_lock;

    public @OriginalName("spinlock_t") spinlock atomic_lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int _do_not_use[4]; unsigned int prefix[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_pcie_tlp_log extends Struct {
    public @Unsigned int @Size(4) [] _do_not_use;

    public @Unsigned int @Size(4) [] prefix;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int dw[14]; struct { unsigned int _do_not_use[4]; unsigned int prefix[4]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pcie_tlp_log extends Union {
    public @Unsigned int @Size(14) [] dw;

    public anon_member_of_anon_member_of_pcie_tlp_log anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct __kfifo kfifo; struct aer_err_source *type; const struct aer_err_source *const_type; u8 (*rectype)[0]; struct aer_err_source *ptr; const struct aer_err_source *ptr_const; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_aer_fifo_of_aer_rpc extends Union {
    public __kfifo kfifo;

    public Ptr<aer_err_source> type;

    public Ptr<aer_err_source> const_type;

    public Ptr<char @Size(0) []> rectype;

    public Ptr<aer_err_source> ptr;

    public Ptr<aer_err_source> ptr_const;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int vm_st_valid; long long unsigned int vm_xst_valid; long long unsigned int vm_ph_ignore; long long unsigned int rsvd1; long long unsigned int vm_st; long long unsigned int vm_xst; long long unsigned int pm_st_valid; long long unsigned int pm_xst_valid; long long unsigned int pm_ph_ignore; long long unsigned int rsvd2; long long unsigned int pm_st; long long unsigned int pm_xst; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_st_info extends Struct {
    public @Unsigned long vm_st_valid;

    public @Unsigned long vm_xst_valid;

    public @Unsigned long vm_ph_ignore;

    public @Unsigned long rsvd1;

    public @Unsigned long vm_st;

    public @Unsigned long vm_xst;

    public @Unsigned long pm_st_valid;

    public @Unsigned long pm_xst_valid;

    public @Unsigned long pm_ph_ignore;

    public @Unsigned long rsvd2;

    public @Unsigned long pm_st;

    public @Unsigned long pm_xst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 *screen_base; u8 *screen_buffer; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fb_info extends Union {
    public String screen_base;

    public String screen_buffer;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct acpi_processor_cx states[8]; struct acpi_lpi_state lpi_states[8]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acpi_processor_power extends Union {
    public acpi_processor_cx @Size(8) [] states;

    public acpi_lpi_state @Size(8) [] lpi_states;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int (*probe_table)(struct acpi_table_header*); int (*probe_subtbl)(union acpi_subtable_headers*, const long unsigned int); }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acpi_probe_entry extends Union {
    public @OriginalName("acpi_tbl_table_handler") Ptr<?> probe_table;

    public @OriginalName("acpi_tbl_entry_handler") Ptr<?> probe_subtbl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __Empty_source; u8 source[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_acpi_pci_routing_table extends Struct {
    public lockdep_map_p __Empty_source;

    public char @Size(0) [] source;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 pad[4]; struct { struct { } __Empty_source; u8 source[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acpi_pci_routing_table extends Union {
    public char @Size(4) [] pad;

    public anon_member_of_anon_member_of_acpi_pci_routing_table anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int lower; unsigned int upper; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pn_and_anon_member_of_pn_t_and_serial_number_of_cper_sec_pcie extends Struct {
    public @Unsigned int lower;

    public @Unsigned int upper;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct acpi_hest_generic *generic; struct acpi_hest_generic_v2 *generic_v2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ghes extends Union {
    public Ptr<acpi_hest_generic> generic;

    public Ptr<acpi_hest_generic_v2> generic_v2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 function; u8 device; u8 bus; short unsigned int segment; u8 reserved_1[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_agent_addr_of_cxl_cper_sec_prot_err extends Struct {
    public char function;

    public char device;

    public char bus;

    public @Unsigned short segment;

    public char @Size(3) [] reserved_1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int segment_start; short unsigned int segment_end; short unsigned int bdf_start; short unsigned int bdf_end; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_viot_endpoint extends Struct {
    public @Unsigned short segment_start;

    public @Unsigned short segment_end;

    public @Unsigned short bdf_start;

    public @Unsigned short bdf_end;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int segment_start; short unsigned int segment_end; short unsigned int bdf_start; short unsigned int bdf_end; }; long long unsigned int address; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_viot_endpoint extends Union {
    public anon_member_of_anon_member_of_viot_endpoint anon0;

    public @Unsigned long address;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { spinlock slock; long unsigned int lock_flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_generic_pm_domain extends Struct {
    public @OriginalName("spinlock_t") spinlock slock;

    public @Unsigned long lock_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct mutex mlock; struct { spinlock slock; long unsigned int lock_flags; }; struct { raw_spinlock raw_slock; long unsigned int raw_lock_flags; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_generic_pm_domain extends Union {
    public mutex mlock;

    public anon_member_of_anon_member_of_generic_pm_domain anon1;

    public anon_member_of_anon_member_of_generic_pm_domain anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int features; long long unsigned int features_array[2]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_virtio_device extends Union {
    public @Unsigned long features;

    public @Unsigned long @Size(2) [] features_array;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct vring_virtqueue_split split; struct vring_virtqueue_packed packed; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vring_virtqueue extends Union {
    public vring_virtqueue_split split;

    public vring_virtqueue_packed packed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int size; unsigned int reserved; } parts_size; struct { unsigned int count; unsigned int reserved; } hdr_list_count; struct { unsigned int count; unsigned int reserved; struct virtio_dev_part_hdr hdrs[0]; } hdr_list; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_virtio_admin_cmd_dev_parts_metadata_result extends Union {
    public parts_size_of_anon_member_of_virtio_admin_cmd_dev_parts_metadata_result parts_size;

    public hdr_list_count_of_anon_member_of_virtio_admin_cmd_dev_parts_metadata_result hdr_list_count;

    public hdr_list_of_anon_member_of_virtio_admin_cmd_dev_parts_metadata_result hdr_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct virtio_pci_legacy_device ldev; struct virtio_pci_modern_device mdev; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_virtio_pci_device extends Union {
    public virtio_pci_legacy_device ldev;

    public virtio_pci_modern_device mdev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int free_page_hint_cmd_id; unsigned int free_page_report_cmd_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_virtio_balloon_config extends Union {
    public @Unsigned @OriginalName("__le32") int free_page_hint_cmd_id;

    public @Unsigned @OriginalName("__le32") int free_page_report_cmd_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct vm_struct *area; } pv; struct { struct page* pages[16]; long unsigned int addrs[16]; void *addr; } hvm; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_xenbus_map_node extends Union {
    public pv_of_anon_member_of_xenbus_map_node pv;

    public hvm_of_anon_member_of_xenbus_map_node hvm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_bmSublinkSpeedAttr; unsigned int bmSublinkSpeedAttr[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_usb_ssp_cap_descriptor extends Struct {
    public lockdep_map_p __empty_bmSublinkSpeedAttr;

    public @Unsigned @OriginalName("__le32") int @Size(0) [] bmSublinkSpeedAttr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int legacy_padding; struct { struct { } __empty_bmSublinkSpeedAttr; unsigned int bmSublinkSpeedAttr[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_usb_ssp_cap_descriptor extends Union {
    public @Unsigned @OriginalName("__le32") int legacy_padding;

    public anon_member_of_anon_member_of_usb_ssp_cap_descriptor anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *hyp_attr_data; long unsigned int hyp_attr_value; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hyp_sysfs_attr extends Union {
    public Ptr<?> hyp_attr_data;

    public @Unsigned long hyp_attr_value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { _Bool slave; _Bool target; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_spi_controller extends Union {
    public boolean slave;

    public boolean target;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 salt[32]; u8 scratch[32]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tpm2_auth extends Union {
    public char @Size(32) [] salt;

    public char @Size(32) [] scratch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct client_hdr client; struct server_hdr server; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acpi_tcpa extends Union {
    public client_hdr client;

    public server_hdr server;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int ttbr; struct { unsigned int ips; unsigned int tg; unsigned int sh; unsigned int orgn; unsigned int irgn; unsigned int tsz; } tcr; long long unsigned int mair; } arm_lpae_s1_cfg; struct { long long unsigned int vttbr; struct { unsigned int ps; unsigned int tg; unsigned int sh; unsigned int orgn; unsigned int irgn; unsigned int sl; unsigned int tsz; } vtcr; } arm_lpae_s2_cfg; struct { unsigned int ttbr; unsigned int tcr; unsigned int nmrr; unsigned int prrr; } arm_v7s_cfg; struct { long long unsigned int transtab; long long unsigned int memattr; } arm_mali_lpae_cfg; struct { long long unsigned int ttbr[4]; unsigned int n_ttbrs; } apple_dart_cfg; struct { int nid; } amd; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_io_pgtable_cfg extends Union {
    public arm_lpae_s1_cfg_of_anon_member_of_io_pgtable_cfg arm_lpae_s1_cfg;

    public arm_lpae_s2_cfg_of_anon_member_of_io_pgtable_cfg arm_lpae_s2_cfg;

    public arm_v7s_cfg_of_anon_member_of_io_pgtable_cfg arm_v7s_cfg;

    public arm_mali_lpae_cfg_of_anon_member_of_io_pgtable_cfg arm_mali_lpae_cfg;

    public apple_dart_cfg_of_anon_member_of_io_pgtable_cfg apple_dart_cfg;

    public amd_of_anon_member_of_io_pgtable_cfg amd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int data[4]; __int128 unsigned data128[2]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dev_table_entry extends Union {
    public @Unsigned long @Size(4) [] data;

    public me.bechberger.ebpf.type.BPFType.BPFIntType. @Unsigned Int128 @Size(2) [] data128;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { union irte_ga_lo lo; union irte_ga_hi hi; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_irte_ga extends Struct {
    public irte_ga_lo lo;

    public irte_ga_hi hi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { union irte_ga_lo lo; union irte_ga_hi hi; }; __int128 unsigned irte; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_irte_ga extends Union {
    public anon_member_of_anon_member_of_irte_ga anon0;

    public me.bechberger.ebpf.type.BPFType.BPFIntType. @Unsigned Int128 irte;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int ext; unsigned int hidh; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ivhd_entry_and_ext_hid_of_anon_member_of_ivhd_entry extends Struct {
    public @Unsigned int ext;

    public @Unsigned int hidh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int ext; unsigned int hidh; }; struct { unsigned int ext; unsigned int hidh; } ext_hid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ivhd_entry extends Union {
    public anon_member_of_anon_member_of_ivhd_entry_and_ext_hid_of_anon_member_of_ivhd_entry anon0;

    public anon_member_of_anon_member_of_ivhd_entry_and_ext_hid_of_anon_member_of_ivhd_entry ext_hid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int reserved_0; long long unsigned int dest_mode_logical; long long unsigned int reserved_1; long long unsigned int destid_0_23; long long unsigned int vector; long long unsigned int reserved_2; long long unsigned int destid_24_31; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_intcapxt extends Struct {
    public @Unsigned long reserved_0;

    public @Unsigned long dest_mode_logical;

    public @Unsigned long reserved_1;

    public @Unsigned long destid_0_23;

    public @Unsigned long vector;

    public @Unsigned long reserved_2;

    public @Unsigned long destid_24_31;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int present; long long unsigned int fpd; long long unsigned int __res0; long long unsigned int avail; long long unsigned int __res1; long long unsigned int pst; long long unsigned int vector; long long unsigned int __res2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_anon_member_of_irte extends Struct {
    public @Unsigned long present;

    public @Unsigned long fpd;

    public @Unsigned long __res0;

    public @Unsigned long avail;

    public @Unsigned long __res1;

    public @Unsigned long pst;

    public @Unsigned long vector;

    public @Unsigned long __res2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int present; long long unsigned int fpd; long long unsigned int __res0; long long unsigned int avail; long long unsigned int __res1; long long unsigned int pst; long long unsigned int vector; long long unsigned int __res2; }; struct { long long unsigned int r_present; long long unsigned int r_fpd; long long unsigned int dst_mode; long long unsigned int redir_hint; long long unsigned int trigger_mode; long long unsigned int dlvry_mode; long long unsigned int r_avail; long long unsigned int r_res0; long long unsigned int r_vector; long long unsigned int r_res1; long long unsigned int dest_id; }; struct { long long unsigned int p_present; long long unsigned int p_fpd; long long unsigned int p_res0; long long unsigned int p_avail; long long unsigned int p_res1; long long unsigned int p_urgent; long long unsigned int p_pst; long long unsigned int p_vector; long long unsigned int p_res2; long long unsigned int pda_l; }; long long unsigned int low; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_irte extends Union {
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_irte anon0;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_irte anon1;

    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_irte anon2;

    public @Unsigned long low;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { union { struct { long long unsigned int present; long long unsigned int fpd; long long unsigned int __res0; long long unsigned int avail; long long unsigned int __res1; long long unsigned int pst; long long unsigned int vector; long long unsigned int __res2; }; struct { long long unsigned int r_present; long long unsigned int r_fpd; long long unsigned int dst_mode; long long unsigned int redir_hint; long long unsigned int trigger_mode; long long unsigned int dlvry_mode; long long unsigned int r_avail; long long unsigned int r_res0; long long unsigned int r_vector; long long unsigned int r_res1; long long unsigned int dest_id; }; struct { long long unsigned int p_present; long long unsigned int p_fpd; long long unsigned int p_res0; long long unsigned int p_avail; long long unsigned int p_res1; long long unsigned int p_urgent; long long unsigned int p_pst; long long unsigned int p_vector; long long unsigned int p_res2; long long unsigned int pda_l; }; long long unsigned int low; }; union { struct { long long unsigned int sid; long long unsigned int sq; long long unsigned int svt; long long unsigned int __res3; }; struct { long long unsigned int p_sid; long long unsigned int p_sq; long long unsigned int p_svt; long long unsigned int p_res3; long long unsigned int pda_h; }; long long unsigned int high; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_irte extends Struct {
    @InlineUnion(43678)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_irte anon0$0;

    @InlineUnion(43678)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_irte anon0$1;

    @InlineUnion(43678)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_irte anon0$2;

    @InlineUnion(43678)
    public @Unsigned long low;

    @InlineUnion(43681)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_irte anon1$0;

    @InlineUnion(43681)
    public anon_member_of_anon_member_of_anon_member_of_anon_member_of_irte anon1$1;

    @InlineUnion(43681)
    public @Unsigned long high;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { union { struct { long long unsigned int present; long long unsigned int fpd; long long unsigned int __res0; long long unsigned int avail; long long unsigned int __res1; long long unsigned int pst; long long unsigned int vector; long long unsigned int __res2; }; struct { long long unsigned int r_present; long long unsigned int r_fpd; long long unsigned int dst_mode; long long unsigned int redir_hint; long long unsigned int trigger_mode; long long unsigned int dlvry_mode; long long unsigned int r_avail; long long unsigned int r_res0; long long unsigned int r_vector; long long unsigned int r_res1; long long unsigned int dest_id; }; struct { long long unsigned int p_present; long long unsigned int p_fpd; long long unsigned int p_res0; long long unsigned int p_avail; long long unsigned int p_res1; long long unsigned int p_urgent; long long unsigned int p_pst; long long unsigned int p_vector; long long unsigned int p_res2; long long unsigned int pda_l; }; long long unsigned int low; }; union { struct { long long unsigned int sid; long long unsigned int sq; long long unsigned int svt; long long unsigned int __res3; }; struct { long long unsigned int p_sid; long long unsigned int p_sq; long long unsigned int p_svt; long long unsigned int p_res3; long long unsigned int pda_h; }; long long unsigned int high; }; }; __int128 unsigned irte; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_irte extends Union {
    public anon_member_of_anon_member_of_irte anon0;

    public me.bechberger.ebpf.type.BPFType.BPFIntType. @Unsigned Int128 irte;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct dma_pte *pgd; int gaw; int agaw; long long unsigned int max_addr; spinlock s1_lock; struct list_head s1_domains; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_dmar_domain extends Struct {
    public Ptr<dma_pte> pgd;

    public int gaw;

    public int agaw;

    public @Unsigned long max_addr;

    public @OriginalName("spinlock_t") spinlock s1_lock;

    public list_head s1_domains;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct dma_pte *pgd; int gaw; int agaw; long long unsigned int max_addr; spinlock s1_lock; struct list_head s1_domains; }; struct { struct dmar_domain *s2_domain; struct iommu_hwpt_vtd_s1 s1_cfg; struct list_head s2_link; }; struct { struct mmu_notifier notifier; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dmar_domain extends Union {
    public anon_member_of_anon_member_of_dmar_domain anon0;

    public anon_member_of_anon_member_of_dmar_domain anon1;

    public anon_member_of_anon_member_of_dmar_domain anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int type; long long unsigned int pasid_present; long long unsigned int rsvd; long long unsigned int rid; long long unsigned int pasid; long long unsigned int exe_req; long long unsigned int pm_req; long long unsigned int rsvd2; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_page_req_dsc extends Struct {
    public @Unsigned long type;

    public @Unsigned long pasid_present;

    public @Unsigned long rsvd;

    public @Unsigned long rid;

    public @Unsigned long pasid;

    public @Unsigned long exe_req;

    public @Unsigned long pm_req;

    public @Unsigned long rsvd2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int type; long long unsigned int pasid_present; long long unsigned int rsvd; long long unsigned int rid; long long unsigned int pasid; long long unsigned int exe_req; long long unsigned int pm_req; long long unsigned int rsvd2; }; long long unsigned int qw_0; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_page_req_dsc extends Union {
    public anon_member_of_anon_member_of_page_req_dsc anon0;

    public @Unsigned long qw_0;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __Empty_device_name; u8 device_name[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_acpi_dmar_andd extends Struct {
    public lockdep_map_p __Empty_device_name;

    public char @Size(0) [] device_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 __pad; struct { struct { } __Empty_device_name; u8 device_name[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_acpi_dmar_andd extends Union {
    public char __pad;

    public anon_member_of_anon_member_of_acpi_dmar_andd anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct msi_msg msi_entry; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_intel_ir_data extends Union {
    public msi_msg msi_entry;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct mutex mutex; raw_spinlock spinlock; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fsl_mc_io extends Union {
    public mutex mutex;

    public @OriginalName("raw_spinlock_t") raw_spinlock spinlock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct iova_fq *single_fq; struct iova_fq *percpu_fq; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iommu_dma_cookie extends Union {
    public Ptr<iova_fq> single_fq;

    public Ptr<iova_fq> percpu_fq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int size; struct iova_magazine *next; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_iova_magazine extends Union {
    public @Unsigned long size;

    public Ptr<iova_magazine> next;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int head; struct virtio_iommu_fault fault; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_viommu_event extends Union {
    public @Unsigned int head;

    public virtio_iommu_fault fault;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct anon_transport_class"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_transport_class extends Struct {
    public transport_class tclass;

    public attribute_container container;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { spinlock spinlock; long unsigned int spinlock_flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_regmap extends Struct {
    public @OriginalName("spinlock_t") spinlock spinlock;

    public @Unsigned long spinlock_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct mutex mutex; struct { spinlock spinlock; long unsigned int spinlock_flags; }; struct { raw_spinlock raw_spinlock; long unsigned int raw_spinlock_flags; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_regmap extends Union {
    public mutex mutex;

    public anon_member_of_anon_member_of_regmap anon1;

    public anon_member_of_anon_member_of_regmap anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *mem; void *iomem; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nvdimm_map extends Union {
    public Ptr<?> mem;

    public Ptr<?> iomem;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct nvdimm_cxl_label cxl; struct nvdimm_efi_label efi; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nd_namespace_label extends Union {
    public nvdimm_cxl_label cxl;

    public nvdimm_efi_label efi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct dma_fence_cb cb; struct irq_work work; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dma_fence_chain extends Union {
    public dma_fence_cb cb;

    public irq_work work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void* reserved[1]; void *unused; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_cdrom_generic_command extends Union {
    public Ptr<?> @Size(1) [] reserved;

    public Ptr<?> unused;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 error; u8 feature; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ata_taskfile extends Union {
    public char error;

    public char feature;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int id[256]; unsigned int gscr[128]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ata_device extends Union {
    public @Unsigned short @Size(256) [] id;

    public @Unsigned int @Size(128) [] gscr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct hdr_static_metadata hdmi_type1; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hdr_sink_metadata extends Union {
    public hdr_static_metadata hdmi_type1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 cpp[4]; u8 char_per_block[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_drm_format_info extends Union {
    public char @Size(4) [] cpp;

    public char @Size(4) [] char_per_block;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 mfg_id[2]; u8 prod_code[2]; unsigned int serial; u8 mfg_week; u8 mfg_year; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_edid extends Struct {
    public char @Size(2) [] mfg_id;

    public char @Size(2) [] prod_code;

    public @Unsigned int serial;

    public char mfg_week;

    public char mfg_year;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct drm_edid_product_id product_id; struct { u8 mfg_id[2]; u8 prod_code[2]; unsigned int serial; u8 mfg_week; u8 mfg_year; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_edid extends Union {
    public drm_edid_product_id product_id;

    public anon_member_of_anon_member_of_edid anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct drm_gpuva_op_map map; struct drm_gpuva_op_remap remap; struct drm_gpuva_op_unmap unmap; struct drm_gpuva_op_prefetch prefetch; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_drm_gpuva_op extends Union {
    public drm_gpuva_op_map map;

    public drm_gpuva_op_remap remap;

    public drm_gpuva_op_unmap unmap;

    public drm_gpuva_op_prefetch prefetch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { u8 offset; u8 length; } alpha; struct { u8 offset; u8 length; } red; struct { u8 offset; u8 length; } green; struct { u8 offset; u8 length; } blue; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_pixel_format extends Struct {
    public alpha_of_anon_member_of_anon_member_of_pixel_format_and_blue_of_anon_member_of_anon_member_of_pixel_format_and_green_of_anon_member_of_anon_member_of_pixel_format alpha;

    public alpha_of_anon_member_of_anon_member_of_pixel_format_and_blue_of_anon_member_of_anon_member_of_pixel_format_and_green_of_anon_member_of_anon_member_of_pixel_format red;

    public alpha_of_anon_member_of_anon_member_of_pixel_format_and_blue_of_anon_member_of_anon_member_of_pixel_format_and_green_of_anon_member_of_anon_member_of_pixel_format green;

    public alpha_of_anon_member_of_anon_member_of_pixel_format_and_blue_of_anon_member_of_anon_member_of_pixel_format_and_green_of_anon_member_of_anon_member_of_pixel_format blue;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { u8 offset; u8 length; } alpha; struct { u8 offset; u8 length; } red; struct { u8 offset; u8 length; } green; struct { u8 offset; u8 length; } blue; }; struct { u8 offset; u8 length; } index; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_pixel_format extends Union {
    public anon_member_of_anon_member_of_pixel_format anon0;

    public alpha_of_anon_member_of_anon_member_of_pixel_format_and_blue_of_anon_member_of_anon_member_of_pixel_format_and_green_of_anon_member_of_anon_member_of_pixel_format index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct spi_offload_trigger_periodic periodic; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_spi_offload_trigger_config extends Union {
    public spi_offload_trigger_periodic periodic;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int optical_wavelength; short unsigned int cable_compliance; struct { u8 sff8431_app_e; u8 fc_pi_4_app_h; u8 reserved60_2; u8 reserved61; } passive; struct { u8 sff8431_app_e; u8 fc_pi_4_app_h; u8 sff8431_lim; u8 fc_pi_4_lim; u8 reserved60_4; u8 reserved61; } active; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sfp_eeprom_base extends Union {
    public @Unsigned @OriginalName("__be16") short optical_wavelength;

    public @Unsigned @OriginalName("__be16") short cable_compliance;

    public passive_of_anon_member_of_sfp_eeprom_base passive;

    public active_of_anon_member_of_sfp_eeprom_base active;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct net_device *netdev; struct phy_device *phydev; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_macsec_context_and_upstream_of_phy_device_node extends Union {
    public Ptr<net_device> netdev;

    public Ptr<phy_device> phydev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { enum ethtool_c33_pse_ext_substate_error_condition error_condition; enum ethtool_c33_pse_ext_substate_mr_pse_enable mr_pse_enable; enum ethtool_c33_pse_ext_substate_option_detect_ted option_detect_ted; enum ethtool_c33_pse_ext_substate_option_vport_lim option_vport_lim; enum ethtool_c33_pse_ext_substate_ovld_detected ovld_detected; enum ethtool_c33_pse_ext_substate_power_not_available power_not_available; enum ethtool_c33_pse_ext_substate_short_detected short_detected; unsigned int __c33_pse_ext_substate; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_c33_pse_ext_state_info extends Union {
    public ethtool_c33_pse_ext_substate_error_condition error_condition;

    public ethtool_c33_pse_ext_substate_mr_pse_enable mr_pse_enable;

    public ethtool_c33_pse_ext_substate_option_detect_ted option_detect_ted;

    public ethtool_c33_pse_ext_substate_option_vport_lim option_vport_lim;

    public ethtool_c33_pse_ext_substate_ovld_detected ovld_detected;

    public ethtool_c33_pse_ext_substate_power_not_available power_not_available;

    public ethtool_c33_pse_ext_substate_short_detected short_detected;

    public @Unsigned int __c33_pse_ext_substate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct __kfifo kfifo; struct pse_ntf *type; const struct pse_ntf *const_type; u8 (*rectype)[0]; struct pse_ntf *ptr; const struct pse_ntf *ptr_const; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ntf_fifo_of_pse_controller_dev extends Union {
    public __kfifo kfifo;

    public Ptr<pse_ntf> type;

    public Ptr<pse_ntf> const_type;

    public Ptr<char @Size(0) []> rectype;

    public Ptr<pse_ntf> ptr;

    public Ptr<pse_ntf> ptr_const;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int csum_start; short unsigned int csum_offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_virtio_net_hdr_v1 extends Struct {
    public @Unsigned @OriginalName("__virtio16") short csum_start;

    public @Unsigned @OriginalName("__virtio16") short csum_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int csum_start; short unsigned int csum_offset; }; struct { short unsigned int start; short unsigned int offset; } csum; struct { short unsigned int segments; short unsigned int dup_acks; } rsc; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_virtio_net_hdr_v1 extends Union {
    public anon_member_of_anon_member_of_virtio_net_hdr_v1 anon0;

    public csum_of_anon_member_of_virtio_net_hdr_v1 csum;

    public rsc_of_anon_member_of_virtio_net_hdr_v1 rsc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct fib_nh_common fib_nhc; struct fib_nh fib_nh; struct fib6_nh fib6_nh; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nh_info extends Union {
    public fib_nh_common fib_nhc;

    public fib_nh fib_nh;

    public fib6_nh fib6_nh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { int counter; } upper_bound; } hthr; struct { struct list_head uw_nh_entry; short unsigned int count_buckets; short unsigned int wants_buckets; } res; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nh_grp_entry extends Union {
    public hthr_of_anon_member_of_nh_grp_entry hthr;

    public res_of_anon_member_of_nh_grp_entry res;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct nh_info *nh_info; struct nh_group *nh_grp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nexthop extends Union {
    public Ptr<nh_info> nh_info;

    public Ptr<nh_group> nh_grp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int short_addr; long long unsigned int extended_addr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ieee802154_addr extends Union {
    public @Unsigned @OriginalName("__le16") short short_addr;

    public @Unsigned @OriginalName("__le64") long extended_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int queue_index; unsigned int ifindex; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tun_file extends Union {
    public @Unsigned short queue_index;

    public @Unsigned int ifindex;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct virtio_net_hdr hdr; struct virtio_net_hdr_mrg_rxbuf mrg_hdr; struct virtio_net_hdr_v1_hash hash_v1_hdr; struct virtio_net_hdr_v1_hash_tunnel tnl_hdr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_virtio_net_common_hdr extends Union {
    public virtio_net_hdr hdr;

    public virtio_net_hdr_mrg_rxbuf mrg_hdr;

    public virtio_net_hdr_v1_hash hash_v1_hdr;

    public virtio_net_hdr_v1_hash_tunnel tnl_hdr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct vcap_u1_key u1; struct vcap_u32_key u32; struct vcap_u48_key u48; struct vcap_u56_key u56; struct vcap_u64_key u64; struct vcap_u72_key u72; struct vcap_u112_key u112; struct vcap_u128_key u128; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vcap_client_keyfield_data extends Union {
    public vcap_u1_key u1;

    public vcap_u32_key u32;

    public vcap_u48_key u48;

    public vcap_u56_key u56;

    public vcap_u64_key u64;

    public vcap_u72_key u72;

    public vcap_u112_key u112;

    public vcap_u128_key u128;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct vcap_u1_action u1; struct vcap_u32_action u32; struct vcap_u48_action u48; struct vcap_u56_action u56; struct vcap_u64_action u64; struct vcap_u72_action u72; struct vcap_u112_action u112; struct vcap_u128_action u128; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vcap_client_actionfield_data extends Union {
    public vcap_u1_action u1;

    public vcap_u32_action u32;

    public vcap_u48_action u48;

    public vcap_u56_action u56;

    public vcap_u64_action u64;

    public vcap_u72_action u72;

    public vcap_u112_action u112;

    public vcap_u128_action u128;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int chain_index; struct net_device *dev; struct { short unsigned int vid; short unsigned int proto; u8 prio; } vlan; struct { u8 dst[6]; u8 src[6]; } vlan_push_eth; struct { enum flow_action_mangle_base htype; unsigned int offset; unsigned int mask; unsigned int val; } mangle; struct ip_tunnel_info *tunnel; unsigned int csum_flags; unsigned int mark; short unsigned int ptype; short unsigned int rx_queue; unsigned int priority; struct { unsigned int ctx; unsigned int index; u8 vf; } queue; struct { struct psample_group *psample_group; unsigned int rate; unsigned int trunc_size; _Bool truncate; } sample; struct { unsigned int burst; long long unsigned int rate_bytes_ps; long long unsigned int peakrate_bytes_ps; unsigned int avrate; short unsigned int overhead; long long unsigned int burst_pkt; long long unsigned int rate_pkt_ps; unsigned int mtu; struct { enum flow_action_id act_id; unsigned int extval; } exceed; struct { enum flow_action_id act_id; unsigned int extval; } notexceed; } police; struct { int action; short unsigned int zone; nf_flowtable *flow_table; } ct; struct { long unsigned int cookie; unsigned int mark; unsigned int labels[4]; _Bool orig_dir; } ct_metadata; struct { unsigned int label; short unsigned int proto; u8 tc; u8 bos; u8 ttl; } mpls_push; struct { short unsigned int proto; } mpls_pop; struct { unsigned int label; u8 tc; u8 bos; u8 ttl; } mpls_mangle; struct { int prio; long long unsigned int basetime; long long unsigned int cycletime; long long unsigned int cycletimeext; unsigned int num_entries; struct action_gate_entry *entries; } gate; struct { short unsigned int sid; } pppoe; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_flow_action_entry extends Union {
    public @Unsigned int chain_index;

    public Ptr<net_device> dev;

    public vlan_of_anon_member_of_flow_action_entry vlan;

    public vlan_push_eth_of_anon_member_of_flow_action_entry vlan_push_eth;

    public mangle_of_anon_member_of_flow_action_entry mangle;

    public Ptr<ip_tunnel_info> tunnel;

    public @Unsigned int csum_flags;

    public @Unsigned int mark;

    public @Unsigned short ptype;

    public @Unsigned short rx_queue;

    public @Unsigned int priority;

    public queue_of_anon_member_of_flow_action_entry queue;

    public sample_of_anon_member_of_flow_action_entry sample;

    public police_of_anon_member_of_flow_action_entry police;

    public ct_of_anon_member_of_flow_action_entry ct;

    public ct_metadata_of_anon_member_of_flow_action_entry ct_metadata;

    public mpls_push_of_anon_member_of_flow_action_entry mpls_push;

    public mpls_pop_of_anon_member_of_flow_action_entry mpls_pop;

    public mpls_mangle_of_anon_member_of_flow_action_entry mpls_mangle;

    public gate_of_anon_member_of_flow_action_entry gate;

    public pppoe_of_anon_member_of_flow_action_entry pppoe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int vlan_id; short unsigned int vlan_dei; short unsigned int vlan_priority; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_flow_dissector_key_vlan extends Struct {
    public @Unsigned short vlan_id;

    public @Unsigned short vlan_dei;

    public @Unsigned short vlan_priority;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int vlan_id; short unsigned int vlan_dei; short unsigned int vlan_priority; }; short unsigned int vlan_tci; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_flow_dissector_key_vlan extends Union {
    public anon_member_of_anon_member_of_flow_dissector_key_vlan anon0;

    public @Unsigned @OriginalName("__be16") short vlan_tci;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int src; short unsigned int dst; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_flow_dissector_key_ports extends Struct {
    public @Unsigned @OriginalName("__be16") short src;

    public @Unsigned @OriginalName("__be16") short dst;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ports; struct { short unsigned int src; short unsigned int dst; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_flow_dissector_key_ports extends Union {
    public @Unsigned @OriginalName("__be32") int ports;

    public anon_member_of_anon_member_of_flow_dissector_key_ports anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int order; unsigned int pool_size; int nid; struct device *dev; struct napi_struct *napi; enum dma_data_direction dma_dir; unsigned int max_len; unsigned int offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_page_pool_params extends Struct {
    public @Unsigned int order;

    public @Unsigned int pool_size;

    public int nid;

    public Ptr<device> dev;

    public Ptr<napi_struct> napi;

    public dma_data_direction dma_dir;

    public @Unsigned int max_len;

    public @Unsigned int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int order; unsigned int pool_size; int nid; struct device *dev; struct napi_struct *napi; enum dma_data_direction dma_dir; unsigned int max_len; unsigned int offset; }; struct page_pool_params_fast fast; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_page_pool_params extends Union {
    public anon_member_of_anon_member_of_page_pool_params anon0;

    public page_pool_params_fast fast;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int number_of_packets; unsigned int stream_id; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_usbdevfs_urb extends Union {
    public int number_of_packets;

    public @Unsigned int stream_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int reserved3[9]; unsigned int usbmode; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ehci_regs extends Struct {
    public @Unsigned int @Size(9) [] reserved3;

    public @Unsigned int usbmode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int port_status[15]; struct { unsigned int reserved3[9]; unsigned int usbmode; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ehci_regs extends Union {
    public @Unsigned int @Size(15) [] port_status;

    public anon_member_of_anon_member_of_ehci_regs anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_wData; short unsigned int wData[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_usb_string_descriptor extends Struct {
    public lockdep_map_p __empty_wData;

    public @Unsigned @OriginalName("__le16") short @Size(0) [] wData;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int legacy_padding; struct { struct { } __empty_wData; short unsigned int wData[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_usb_string_descriptor extends Union {
    public @Unsigned @OriginalName("__le16") short legacy_padding;

    public anon_member_of_anon_member_of_usb_string_descriptor anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_data; u8 data[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_gsb_buffer_and_anon_member_of_anon_member_of_xdp_page_head extends Struct {
    public lockdep_map_p __empty_data;

    public char @Size(0) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int wdata; u8 bdata; struct { struct { } __empty_data; u8 data[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_gsb_buffer extends Union {
    public @Unsigned short wdata;

    public char bdata;

    public anon_member_of_anon_member_of_gsb_buffer_and_anon_member_of_anon_member_of_xdp_page_head anon2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ptp_clock_time start; struct ptp_clock_time phase; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ptp_perout_request extends Union {
    public ptp_clock_time start;

    public ptp_clock_time phase;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ptp_extts_request extts; struct ptp_perout_request perout; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ptp_clock_request extends Union {
    public ptp_extts_request extts;

    public ptp_perout_request perout;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int timestamp; long long int offset; struct pps_event_time pps_times; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ptp_clock_event extends Union {
    public @Unsigned long timestamp;

    public long offset;

    public pps_event_time pps_times;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void *local_table; long long unsigned int *timestamp; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hfi_instance extends Union {
    public Ptr<?> local_table;

    public Ptr<java.lang. @Unsigned Long> timestamp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int bitmap_offset; struct { short unsigned int offset; short unsigned int size; } ppl; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mdp_superblock_1 extends Union {
    public @Unsigned @OriginalName("__le32") int bitmap_offset;

    public ppl_of_anon_member_of_mdp_superblock_1 ppl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int recovery_offset; long long unsigned int journal_tail; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_md_rdev extends Union {
    public @Unsigned @OriginalName("sector_t") long recovery_offset;

    public @Unsigned @OriginalName("sector_t") long journal_tail;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { const u8 *eph_key; long unsigned int eph_key_size; u8 *sw_secret; } derive_sw_secret; struct { const u8 *raw_key; long unsigned int raw_key_size; u8 *lt_key; } import_key; struct { u8 *lt_key; } generate_key; struct { const u8 *lt_key; long unsigned int lt_key_size; u8 *eph_key; } prepare_key; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dm_wrappedkey_op_args extends Union {
    public derive_sw_secret_of_anon_member_of_dm_wrappedkey_op_args derive_sw_secret;

    public import_key_of_anon_member_of_dm_wrappedkey_op_args import_key;

    public generate_key_of_anon_member_of_dm_wrappedkey_op_args generate_key;

    public prepare_key_of_anon_member_of_dm_wrappedkey_op_args prepare_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int context_u; struct bvec_iter context_bi; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dpages extends Union {
    public @Unsigned int context_u;

    public bvec_iter context_bi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const struct edac_scrub_ops *scrub_ops; const struct edac_ecs_ops *ecs_ops; const struct edac_mem_repair_ops *mem_repair_ops; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_edac_dev_data_and_anon_member_of_edac_dev_feature extends Union {
    public Ptr<edac_scrub_ops> scrub_ops;

    public Ptr<edac_ecs_ops> ecs_ops;

    public Ptr<edac_mem_repair_ops> mem_repair_ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 highest_perf; u8 nominal_perf; u8 lowest_nonlinear_perf; u8 lowest_perf; u8 min_limit_perf; u8 max_limit_perf; u8 bios_min_perf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_perf_cached extends Struct {
    public char highest_perf;

    public char nominal_perf;

    public char lowest_nonlinear_perf;

    public char lowest_perf;

    public char min_limit_perf;

    public char max_limit_perf;

    public char bios_min_perf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct efi_generic_dev_path header; struct efi_acpi_dev_path acpi; struct efi_pci_dev_path pci; struct efi_vendor_dev_path vendor; struct efi_rel_offset_dev_path rel_offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_efi_dev_path extends Union {
    public efi_generic_dev_path header;

    public efi_acpi_dev_path acpi;

    public efi_pci_dev_path pci;

    public efi_vendor_dev_path vendor;

    public efi_rel_offset_dev_path rel_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int pci_addr; long long unsigned int bus_addr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_of_pci_range extends Union {
    public @Unsigned long pci_addr;

    public @Unsigned long bus_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int retval; int size; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hid_bpf_ctx extends Union {
    public int retval;

    public int size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int suspended; long long unsigned int reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_dispatch_suspend_register_and_anon_member_of_hv_explicit_suspend_register_and_anon_member_of_hv_intercept_suspend_register extends Struct {
    public @Unsigned long suspended;

    public @Unsigned long reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 event_pending; u8 event_type; u8 reserved; u8 rsvd[3]; unsigned int exception_type; long long unsigned int context; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_arm64_pending_synthetic_exception_event extends Struct {
    public char event_pending;

    public char event_type;

    public char reserved;

    public char @Size(3) [] rsvd;

    public @Unsigned int exception_type;

    public @Unsigned long context;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int interrupt_shadow; long long unsigned int nmi_masked; long long unsigned int reserved; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_x64_interrupt_state_register extends Struct {
    public @Unsigned long interrupt_shadow;

    public @Unsigned long nmi_masked;

    public @Unsigned long reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int interruption_pending; unsigned int interruption_type; unsigned int deliver_error_code; unsigned int instruction_length; unsigned int nested_event; unsigned int reserved; unsigned int interruption_vector; unsigned int error_code; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_hv_x64_pending_interruption_register extends Struct {
    public @Unsigned int interruption_pending;

    public @Unsigned int interruption_type;

    public @Unsigned int deliver_error_code;

    public @Unsigned int instruction_length;

    public @Unsigned int nested_event;

    public @Unsigned int reserved;

    public @Unsigned int interruption_vector;

    public @Unsigned int error_code;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int disabled; unsigned int __resv; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ce_array extends Struct {
    public @Unsigned int disabled;

    public @Unsigned int __resv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int disabled; unsigned int __resv; }; unsigned int flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ce_array extends Union {
    public anon_member_of_anon_member_of_ce_array anon0;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct dpll_device *dpll; struct dpll_pin *pin; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dpll_pin_ref extends Union {
    public Ptr<dpll_device> dpll;

    public Ptr<dpll_pin> pin;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct ipv6_txoptions *ipv6_opt; struct sk_buff *pktopts; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_inet_request_sock extends Struct {
    public Ptr<ipv6_txoptions> ipv6_opt;

    public Ptr<sk_buff> pktopts;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ip_options_rcu *ireq_opt; struct { struct ipv6_txoptions *ipv6_opt; struct sk_buff *pktopts; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_inet_request_sock extends Union {
    public Ptr<ip_options_rcu> ireq_opt;

    public anon_member_of_anon_member_of_inet_request_sock anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int desc; void *ctx; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ubuf_info_msgzc extends Struct {
    public @Unsigned long desc;

    public Ptr<?> ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long unsigned int desc; void *ctx; }; struct { unsigned int id; short unsigned int len; short unsigned int zerocopy; unsigned int bytelen; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ubuf_info_msgzc extends Union {
    public anon_member_of_anon_member_of_ubuf_info_msgzc anon0;

    public anon_member_of_anon_member_of_ubuf_info_msgzc anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 h_dest[6]; u8 h_source[6]; }; struct { u8 h_dest[6]; u8 h_source[6]; } addrs; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vlan_ethhdr extends Union {
    public addrs_of_anon_member_of_vlan_ethhdr_and_anon_member_of_anon_member_of_vlan_ethhdr anon0;

    public addrs_of_anon_member_of_vlan_ethhdr_and_anon_member_of_anon_member_of_vlan_ethhdr addrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { int mac_offset; int data_offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_skb_gso_cb extends Union {
    public int mac_offset;

    public int data_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int tcp_gso_segs; short unsigned int tcp_gso_size; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_tcp_skb_cb extends Struct {
    public @Unsigned short tcp_gso_segs;

    public @Unsigned short tcp_gso_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int tcp_gso_segs; short unsigned int tcp_gso_size; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tcp_skb_cb extends Union {
    public anon_member_of_anon_member_of_tcp_skb_cb anon0;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct flow_dissector_key_ipv4_addrs v4addrs; struct flow_dissector_key_ipv6_addrs v6addrs; struct flow_dissector_key_tipc tipckey; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_flow_dissector_key_addrs extends Union {
    public flow_dissector_key_ipv4_addrs v4addrs;

    public flow_dissector_key_ipv6_addrs v6addrs;

    public flow_dissector_key_tipc tipckey;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct flow_dissector_key_ports tp_min; struct flow_dissector_key_ports tp_max; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_flow_dissector_key_ports_range extends Struct {
    public flow_dissector_key_ports tp_min;

    public flow_dissector_key_ports tp_max;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct flow_dissector_key_ports tp; struct { struct flow_dissector_key_ports tp_min; struct flow_dissector_key_ports tp_max; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_flow_dissector_key_ports_range extends Union {
    public flow_dissector_key_ports tp;

    public anon_member_of_anon_member_of_flow_dissector_key_ports_range anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 type; u8 code; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_flow_dissector_key_icmp extends Struct {
    public char type;

    public char code;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int act_miss_cookie; unsigned int chain; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tc_skb_ext extends Union {
    public @Unsigned long act_miss_cookie;

    public @Unsigned int chain;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct devlink_port_phys_attrs phys; struct devlink_port_pci_pf_attrs pci_pf; struct devlink_port_pci_vf_attrs pci_vf; struct devlink_port_pci_sf_attrs pci_sf; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_devlink_port_attrs extends Union {
    public devlink_port_phys_attrs phys;

    public devlink_port_pci_pf_attrs pci_pf;

    public devlink_port_pci_vf_attrs pci_vf;

    public devlink_port_pci_sf_attrs pci_sf;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 *name; refcount_struct refcnt; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_devlink_rate extends Struct {
    public String name;

    public @OriginalName("refcount_t") refcount_struct refcnt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct devlink_port *devlink_port; struct { u8 *name; refcount_struct refcnt; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_devlink_rate extends Union {
    public Ptr<devlink_port> devlink_port;

    public anon_member_of_anon_member_of_devlink_rate anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct net_device *netdev; int ifindex; u8 ifname[16]; } type_eth; struct { struct ib_device *ibdev; } type_ib; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_devlink_port extends Union {
    public type_eth_of_anon_member_of_devlink_port type_eth;

    public type_ib_of_anon_member_of_devlink_port type_ib;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct net_device *conduit; struct net_device *user; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dsa_port extends Union {
    public Ptr<net_device> conduit;

    public Ptr<net_device> user;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const struct dsa_port *dp; struct dsa_lag lag; struct dsa_bridge bridge; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dsa_db extends Union {
    public Ptr<dsa_port> dp;

    public dsa_lag lag;

    public dsa_bridge bridge;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int ssci; long long unsigned int pn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_salt_and_anon_member_of_salt_t extends Struct {
    public @Unsigned @OriginalName("ssci_t") int ssci;

    public @Unsigned @OriginalName("__be64") long pn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { pn next_pn_halves; long long unsigned int next_pn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_macsec_rx_sa_and_anon_member_of_macsec_tx_sa extends Union {
    public @OriginalName("pn_t") pn next_pn_halves;

    public @Unsigned long next_pn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct macsec_rx_sa *rx_sa; struct macsec_tx_sa *tx_sa; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sa_of_macsec_context extends Union {
    public Ptr<macsec_rx_sa> rx_sa;

    public Ptr<macsec_tx_sa> tx_sa;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct netdev_notifier_offload_xstats_rd *report_delta; struct netdev_notifier_offload_xstats_ru *report_used; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_netdev_notifier_offload_xstats_info extends Union {
    public Ptr<netdev_notifier_offload_xstats_rd> report_delta;

    public Ptr<netdev_notifier_offload_xstats_ru> report_used;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int remote_ipv4; unsigned int remote_ipv6[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_tunnel_key_and_anon_member_of_bpf_xfrm_state extends Union {
    public @Unsigned int remote_ipv4;

    public @Unsigned int @Size(4) [] remote_ipv6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int tunnel_ext; short unsigned int tunnel_flags; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_tunnel_key extends Union {
    public @Unsigned short tunnel_ext;

    public @Unsigned @OriginalName("__be16") short tunnel_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int saddr; unsigned int daddr; short unsigned int sport; short unsigned int dport; } ipv4; struct { unsigned int saddr[4]; unsigned int daddr[4]; short unsigned int sport; short unsigned int dport; } ipv6; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_sock_tuple extends Union {
    public ipv4_of_anon_member_of_bpf_sock_tuple ipv4;

    public ipv6_of_anon_member_of_bpf_sock_tuple ipv6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int tot_len; short unsigned int mtu_result; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_fib_lookup extends Union {
    public @Unsigned short tot_len;

    public @Unsigned short mtu_result;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int h_vlan_proto; short unsigned int h_vlan_TCI; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_bpf_fib_lookup extends Struct {
    public @Unsigned @OriginalName("__be16") short h_vlan_proto;

    public @Unsigned @OriginalName("__be16") short h_vlan_TCI;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ipv4_nh; unsigned int ipv6_nh[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_redir_neigh extends Union {
    public @Unsigned @OriginalName("__be32") int ipv4_nh;

    public @Unsigned int @Size(4) [] ipv6_nh;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct tls12_crypto_info_aes_gcm_128 aes_gcm_128; struct tls12_crypto_info_aes_gcm_256 aes_gcm_256; struct tls12_crypto_info_chacha20_poly1305 chacha20_poly1305; struct tls12_crypto_info_sm4_gcm sm4_gcm; struct tls12_crypto_info_sm4_ccm sm4_ccm; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tls_crypto_context extends Union {
    public tls12_crypto_info_aes_gcm_128 aes_gcm_128;

    public tls12_crypto_info_aes_gcm_256 aes_gcm_256;

    public tls12_crypto_info_chacha20_poly1305 chacha20_poly1305;

    public tls12_crypto_info_sm4_gcm sm4_gcm;

    public tls12_crypto_info_sm4_ccm sm4_ccm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { void *frag0; unsigned int frag0_len; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_napi_gro_cb extends Struct {
    public Ptr<?> frag0;

    public @Unsigned int frag0_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { void *frag0; unsigned int frag0_len; }; struct { struct sk_buff *last; long unsigned int age; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_napi_gro_cb extends Union {
    public anon_member_of_anon_member_of_napi_gro_cb anon0;

    public anon_member_of_anon_member_of_napi_gro_cb anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int gro_remcsum_start; u8 same_flow; u8 encap_mark; u8 csum_valid; u8 csum_cnt; u8 free; u8 is_ipv6; u8 is_fou; u8 ip_fixedid; u8 recursion_counter; u8 is_flist; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_napi_gro_cb_and_zeroed_of_anon_member_of_napi_gro_cb extends Struct {
    public @Unsigned short gro_remcsum_start;

    public char same_flow;

    public char encap_mark;

    public char csum_valid;

    public char csum_cnt;

    public char free;

    public char is_ipv6;

    public char is_fou;

    public char ip_fixedid;

    public char recursion_counter;

    public char is_flist;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct net_bridge *br; struct net_bridge_port *port; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_net_bridge_vlan extends Union {
    public Ptr<net_bridge> br;

    public Ptr<net_bridge_port> port;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct rtable fake_rtable; struct rt6_info fake_rt6_info; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_net_bridge extends Union {
    public rtable fake_rtable;

    public rt6_info fake_rt6_info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct sk_buff *skb; struct net_dm_hw_entries *hw_entries; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_per_cpu_dm_data extends Union {
    public Ptr<sk_buff> skb;

    public Ptr<net_dm_hw_entries> hw_entries;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct devlink_trap_metadata *hw_metadata; void *pc; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_net_dm_skb_cb extends Union {
    public Ptr<devlink_trap_metadata> hw_metadata;

    public Ptr<?> pc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct in_addr in_saddr; struct in6_addr in6_saddr; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_dst_cache_pcpu extends Union {
    public in_addr in_saddr;

    public in6_addr in6_saddr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct sock *sk; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__bpf_sk_storage_map_and_anon_member_of_bpf_iter__sockmap extends Union {
    public Ptr<sock> sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct tc_qopt_offload_stats stats; struct tc_mq_opt_offload_graft_params graft_params; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tc_mq_qopt_offload extends Union {
    public tc_qopt_offload_stats stats;

    public tc_mq_opt_offload_graft_params graft_params;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int miss_cookie_base; unsigned int act_index; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tcf_exts_miss_cookie extends Struct {
    public @Unsigned int miss_cookie_base;

    public @Unsigned int act_index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct tc_qopt_offload_stats stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tc_fifo_qopt_offload extends Union {
    public tc_qopt_offload_stats stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct netlink_sock *sk; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__netlink extends Union {
    public Ptr<netlink_sock> sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_frame; struct xdp_frame frame[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_xdp_page_head extends Struct {
    public lockdep_map_p __empty_frame;

    public xdp_frame @Size(0) [] frame;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { } __empty_frame; struct xdp_frame frame[0]; }; struct { struct { } __empty_data; u8 data[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_xdp_page_head extends Union {
    public anon_member_of_anon_member_of_xdp_page_head anon0;

    public anon_member_of_anon_member_of_gsb_buffer_and_anon_member_of_anon_member_of_xdp_page_head anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ethtool_flash efl; struct ethtool_drvinfo info; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_devlink_compat extends Union {
    public ethtool_flash efl;

    public ethtool_drvinfo info;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct ethtool_eth_phy_stats phy_stats; struct ethtool_eth_mac_stats mac_stats; struct ethtool_eth_ctrl_stats ctrl_stats; struct ethtool_rmon_stats rmon_stats; struct ethtool_phy_stats phydev_stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_stats_reply_data_and_stats_of_anon_member_of_stats_reply_data extends Struct {
    public ethtool_eth_phy_stats phy_stats;

    public ethtool_eth_mac_stats mac_stats;

    public ethtool_eth_ctrl_stats ctrl_stats;

    public ethtool_rmon_stats rmon_stats;

    public ethtool_phy_stats phydev_stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct ethtool_eth_phy_stats phy_stats; struct ethtool_eth_mac_stats mac_stats; struct ethtool_eth_ctrl_stats ctrl_stats; struct ethtool_rmon_stats rmon_stats; struct ethtool_phy_stats phydev_stats; }; struct { struct ethtool_eth_phy_stats phy_stats; struct ethtool_eth_mac_stats mac_stats; struct ethtool_eth_ctrl_stats ctrl_stats; struct ethtool_rmon_stats rmon_stats; struct ethtool_phy_stats phydev_stats; } stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_stats_reply_data extends Union {
    public anon_member_of_anon_member_of_stats_reply_data_and_stats_of_anon_member_of_stats_reply_data anon0;

    public anon_member_of_anon_member_of_stats_reply_data_and_stats_of_anon_member_of_stats_reply_data stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int epl_len; u8 lpl_len; u8 chk_code; u8 resv1; u8 resv2; u8 payload[120]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ethtool_cmis_cdb_request_and_body_of_anon_member_of_ethtool_cmis_cdb_request extends Struct {
    public @Unsigned @OriginalName("__be16") short epl_len;

    public char lpl_len;

    public char chk_code;

    public char resv1;

    public char resv2;

    public char @Size(120) [] payload;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int epl_len; u8 lpl_len; u8 chk_code; u8 resv1; u8 resv2; u8 payload[120]; }; struct { short unsigned int epl_len; u8 lpl_len; u8 chk_code; u8 resv1; u8 resv2; u8 payload[120]; } body; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ethtool_cmis_cdb_request extends Union {
    public anon_member_of_anon_member_of_ethtool_cmis_cdb_request_and_body_of_anon_member_of_ethtool_cmis_cdb_request anon0;

    public anon_member_of_anon_member_of_ethtool_cmis_cdb_request_and_body_of_anon_member_of_ethtool_cmis_cdb_request body;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int image_size; unsigned int resv1; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_cmis_cdb_start_fw_download_pl extends Struct {
    public @Unsigned @OriginalName("__be32") int image_size;

    public @Unsigned @OriginalName("__be32") int resv1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int image_size; unsigned int resv1; }; struct cmis_cdb_start_fw_download_pl_h head; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_cmis_cdb_start_fw_download_pl extends Union {
    public anon_member_of_anon_member_of_cmis_cdb_start_fw_download_pl anon0;

    public cmis_cdb_start_fw_download_pl_h head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ipv4_daddr; struct in6_addr ipv6_daddr; u8 neigh_header[8]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nf_bridge_info extends Union {
    public @Unsigned @OriginalName("__be32") int ipv4_daddr;

    public in6_addr ipv6_daddr;

    public char @Size(8) [] neigh_header;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ip_mc_list *next; struct ip_mc_list *next_rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ip_mc_list extends Union {
    public Ptr<ip_mc_list> next;

    public Ptr<ip_mc_list> next_rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ipv4_addr_key a4; struct in6_addr a6; unsigned int key[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_inetpeer_addr extends Union {
    public ipv4_addr_key a4;

    public in6_addr a6;

    public @Unsigned int @Size(4) [] key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { int counter; } rid; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_inet_peer extends Struct {
    public atomic_t rid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct { int counter; } rid; }; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_inet_peer extends Union {
    public anon_member_of_anon_member_of_inet_peer anon0;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_imsf_slist_flex; unsigned int imsf_slist_flex[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ip_msfilter extends Struct {
    public lockdep_map_p __empty_imsf_slist_flex;

    public @Unsigned @OriginalName("__be32") int @Size(0) [] imsf_slist_flex;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int imsf_slist[1]; struct { struct { } __empty_imsf_slist_flex; unsigned int imsf_slist_flex[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ip_msfilter extends Union {
    public @Unsigned @OriginalName("__be32") int @Size(1) [] imsf_slist;

    public anon_member_of_anon_member_of_ip_msfilter anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int gf_interface_aux; struct __kernel_sockaddr_storage gf_group_aux; unsigned int gf_fmode_aux; unsigned int gf_numsrc_aux; struct __kernel_sockaddr_storage gf_slist[1]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_group_filter extends Struct {
    public @Unsigned int gf_interface_aux;

    public __kernel_sockaddr_storage gf_group_aux;

    public @Unsigned int gf_fmode_aux;

    public @Unsigned int gf_numsrc_aux;

    public __kernel_sockaddr_storage @Size(1) [] gf_slist;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int gf_interface_aux; struct __kernel_sockaddr_storage gf_group_aux; unsigned int gf_fmode_aux; unsigned int gf_numsrc_aux; struct __kernel_sockaddr_storage gf_slist[1]; }; struct { unsigned int gf_interface; struct __kernel_sockaddr_storage gf_group; unsigned int gf_fmode; unsigned int gf_numsrc; struct __kernel_sockaddr_storage gf_slist_flex[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_group_filter extends Union {
    public anon_member_of_anon_member_of_group_filter anon0;

    public anon_member_of_anon_member_of_group_filter anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int gf_interface_aux; struct __kernel_sockaddr_storage gf_group_aux; unsigned int gf_fmode_aux; unsigned int gf_numsrc_aux; struct __kernel_sockaddr_storage gf_slist[1]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_compat_group_filter extends Struct {
    public @Unsigned int gf_interface_aux;

    public __kernel_sockaddr_storage gf_group_aux;

    public @Unsigned int gf_fmode_aux;

    public @Unsigned int gf_numsrc_aux;

    public __kernel_sockaddr_storage @Size(1) [] gf_slist;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int gf_interface_aux; struct __kernel_sockaddr_storage gf_group_aux; unsigned int gf_fmode_aux; unsigned int gf_numsrc_aux; struct __kernel_sockaddr_storage gf_slist[1]; }; struct { unsigned int gf_interface; struct __kernel_sockaddr_storage gf_group; unsigned int gf_fmode; unsigned int gf_numsrc; struct __kernel_sockaddr_storage gf_slist_flex[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_compat_group_filter extends Union {
    public anon_member_of_anon_member_of_compat_group_filter anon0;

    public anon_member_of_anon_member_of_compat_group_filter anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long long unsigned int data_ack; unsigned int data_ack32; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mptcp_ext extends Union {
    public @Unsigned long data_ack;

    public @Unsigned int data_ack32;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct in_addr addr; struct in6_addr addr6; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mptcp_addr_info extends Union {
    public in_addr addr;

    public in6_addr addr6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int sndr_key; long long unsigned int rcvr_key; long long unsigned int data_seq; unsigned int subflow_seq; short unsigned int data_len; short unsigned int csum; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_mptcp_out_options extends Struct {
    public @Unsigned long sndr_key;

    public @Unsigned long rcvr_key;

    public @Unsigned long data_seq;

    public @Unsigned int subflow_seq;

    public @Unsigned short data_len;

    public @Unsigned @OriginalName("__sum16") short csum;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int sndr_key; long long unsigned int rcvr_key; long long unsigned int data_seq; unsigned int subflow_seq; short unsigned int data_len; short unsigned int csum; }; struct { struct mptcp_addr_info addr; long long unsigned int ahmac; }; struct { struct mptcp_ext ext_copy; long long unsigned int fail_seq; }; struct { unsigned int nonce; unsigned int token; long long unsigned int thmac; u8 hmac[20]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mptcp_out_options extends Union {
    public anon_member_of_anon_member_of_mptcp_out_options anon0;

    public anon_member_of_anon_member_of_mptcp_out_options anon1;

    public anon_member_of_anon_member_of_mptcp_out_options anon2;

    public anon_member_of_anon_member_of_mptcp_out_options anon3;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct tcp_ao_key *ao_key; u8 *traffic_key; unsigned int sne; u8 rcv_next; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_tcp_key extends Struct {
    public Ptr<tcp_ao_key> ao_key;

    public String traffic_key;

    public @Unsigned int sne;

    public char rcv_next;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct tcp_ao_key *ao_key; u8 *traffic_key; unsigned int sne; u8 rcv_next; }; struct tcp_md5sig_key *md5_key; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tcp_key extends Union {
    public anon_member_of_anon_member_of_tcp_key anon0;

    public Ptr<tcp_md5sig_key> md5_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct sock_common *sk_common; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__tcp extends Union {
    public Ptr<sock_common> sk_common;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct udp_sock *udp_sk; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__udp extends Union {
    public Ptr<udp_sock> udp_sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int fc_gw4; struct in6_addr fc_gw6; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_fib_config extends Union {
    public @Unsigned @OriginalName("__be32") int fc_gw4;

    public in6_addr fc_gw6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_tnode; struct key_vector* tnode[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_key_vector extends Struct {
    public lockdep_map_p __empty_tnode;

    public Ptr<key_vector> @Size(0) [] tnode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct hlist_head leaf; struct { struct { } __empty_tnode; struct key_vector* tnode[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_key_vector extends Union {
    public hlist_head leaf;

    public anon_member_of_anon_member_of_key_vector anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct nh_notifier_single_info *nh; struct nh_notifier_grp_info *nh_grp; struct nh_notifier_res_table_info *nh_res_table; struct nh_notifier_res_bucket_info *nh_res_bucket; struct nh_notifier_grp_hw_stats_info *nh_grp_hw_stats; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_nh_notifier_info extends Union {
    public Ptr<nh_notifier_single_info> nh;

    public Ptr<nh_notifier_grp_info> nh_grp;

    public Ptr<nh_notifier_res_table_info> nh_res_table;

    public Ptr<nh_notifier_res_bucket_info> nh_res_bucket;

    public Ptr<nh_notifier_grp_hw_stats_info> nh_grp_hw_stats;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct in_addr vifc_lcl_addr; int vifc_lcl_ifindex; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_vifctl extends Union {
    public in_addr vifc_lcl_addr;

    public int vifc_lcl_ifindex;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int mfc_mcastgrp; unsigned int mfc_origin; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_mfc_cache extends Struct {
    public @Unsigned @OriginalName("__be32") int mfc_mcastgrp;

    public @Unsigned @OriginalName("__be32") int mfc_origin;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { unsigned int mfc_mcastgrp; unsigned int mfc_origin; }; struct mfc_cache_cmp_arg cmparg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mfc_cache extends Union {
    public anon_member_of_anon_member_of_mfc_cache anon0;

    public mfc_cache_cmp_arg cmparg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { union { unsigned int a4; unsigned int a6[4]; struct in6_addr in6; } addr; struct callback_head rcu; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_xfrm_pol_inexact_node extends Union {
    public xfrm_address_t addr;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct unix_sock *unix_sk; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__unix extends Union {
    public Ptr<unix_sock> unix_sk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 nh_flags; long unsigned int event; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_arg_netdev_event extends Union {
    public char nh_flags;

    public @Unsigned long event;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct fib6_info *rt; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_bpf_iter__ipv6_route extends Union {
    public Ptr<fib6_info> rt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_addr; struct in6_addr addr[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_segments_of_ipv6_rpl_sr_hdr extends Struct {
    public lockdep_map_p __empty_addr;

    public in6_addr @Size(0) [] addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int type_be32; struct { unsigned int bit7; unsigned int bit6; unsigned int bit5; unsigned int bit4; unsigned int bit3; unsigned int bit2; unsigned int bit1; unsigned int bit0; unsigned int bit15; unsigned int bit14; unsigned int bit13; unsigned int bit12; unsigned int bit11; unsigned int bit10; unsigned int bit9; unsigned int bit8; unsigned int bit23; unsigned int bit22; unsigned int bit21; unsigned int bit20; unsigned int bit19; unsigned int bit18; unsigned int bit17; unsigned int bit16; } type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ioam6_trace_hdr extends Union {
    public @Unsigned @OriginalName("__be32") int type_be32;

    public type_of_anon_member_of_ioam6_trace_hdr type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct in6_addr mf6c_mcastgrp; struct in6_addr mf6c_origin; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_mfc6_cache extends Struct {
    public in6_addr mf6c_mcastgrp;

    public in6_addr mf6c_origin;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct in6_addr mf6c_mcastgrp; struct in6_addr mf6c_origin; }; struct mfc6_cache_cmp_arg cmparg; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mfc6_cache extends Union {
    public anon_member_of_anon_member_of_mfc6_cache anon0;

    public mfc6_cache_cmp_arg cmparg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct tpacket_hdr_variant1 hv1; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tpacket3_hdr extends Union {
    public tpacket_hdr_variant1 hv1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int ts_usec; unsigned int ts_nsec; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_tpacket_bd_ts extends Union {
    public @Unsigned int ts_usec;

    public @Unsigned int ts_nsec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { long unsigned int *rx_owner_map; struct tpacket_kbdq_core prb_bdqc; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_packet_ring_buffer extends Union {
    public Ptr<java.lang. @Unsigned Long> rx_owner_map;

    public tpacket_kbdq_core prb_bdqc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { int counter; } rr_cur; struct bpf_prog *bpf_prog; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_packet_fanout extends Union {
    public atomic_t rr_cur;

    public Ptr<bpf_prog> bpf_prog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int origlen; struct sockaddr_ll ll; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_sa_of_packet_skb_cb extends Union {
    public @Unsigned int origlen;

    public sockaddr_ll ll;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int start_offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_devlink_nl_dump_state extends Struct {
    public @Unsigned long start_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long long unsigned int start_offset; }; struct { long long unsigned int dump_ts; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_devlink_nl_dump_state extends Union {
    public anon_member_of_anon_member_of_devlink_nl_dump_state anon0;

    public anon_member_of_anon_member_of_devlink_nl_dump_state anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct devlink_dpipe_action *action; struct devlink_dpipe_match *match; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_devlink_dpipe_value extends Union {
    public Ptr<devlink_dpipe_action> action;

    public Ptr<devlink_dpipe_match> match;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { const struct devlink_region_ops *ops; const struct devlink_port_region_ops *port_ops; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_devlink_region extends Union {
    public Ptr<devlink_region_ops> ops;

    public Ptr<devlink_port_region_ops> port_ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { } __empty_ptr_bytes; u8 ptr_bytes[0]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of___compat_iw_event extends Struct {
    public lockdep_map_p __empty_ptr_bytes;

    public char @Size(0) [] ptr_bytes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int pointer; struct { struct { } __empty_ptr_bytes; u8 ptr_bytes[0]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of___compat_iw_event extends Union {
    public @Unsigned @OriginalName("compat_caddr_t") int pointer;

    public anon_member_of_anon_member_of___compat_iw_event anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 rx_tx_mcs7_max_nss; u8 rx_tx_mcs9_max_nss; u8 rx_tx_mcs11_max_nss; u8 rx_tx_mcs13_max_nss; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ieee80211_eht_mcs_nss_supp_20mhz_only extends Struct {
    public char rx_tx_mcs7_max_nss;

    public char rx_tx_mcs9_max_nss;

    public char rx_tx_mcs11_max_nss;

    public char rx_tx_mcs13_max_nss;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 rx_tx_mcs7_max_nss; u8 rx_tx_mcs9_max_nss; u8 rx_tx_mcs11_max_nss; u8 rx_tx_mcs13_max_nss; }; u8 rx_tx_max_nss[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ieee80211_eht_mcs_nss_supp_20mhz_only extends Union {
    public anon_member_of_anon_member_of_ieee80211_eht_mcs_nss_supp_20mhz_only anon0;

    public char @Size(4) [] rx_tx_max_nss;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 rx_tx_mcs9_max_nss; u8 rx_tx_mcs11_max_nss; u8 rx_tx_mcs13_max_nss; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_ieee80211_eht_mcs_nss_supp_bw extends Struct {
    public char rx_tx_mcs9_max_nss;

    public char rx_tx_mcs11_max_nss;

    public char rx_tx_mcs13_max_nss;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 rx_tx_mcs9_max_nss; u8 rx_tx_mcs11_max_nss; u8 rx_tx_mcs13_max_nss; }; u8 rx_tx_max_nss[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ieee80211_eht_mcs_nss_supp_bw extends Union {
    public anon_member_of_anon_member_of_ieee80211_eht_mcs_nss_supp_bw anon0;

    public char @Size(3) [] rx_tx_max_nss;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct ieee80211_eht_mcs_nss_supp_20mhz_only only_20mhz; struct { struct ieee80211_eht_mcs_nss_supp_bw _80; struct ieee80211_eht_mcs_nss_supp_bw _160; struct ieee80211_eht_mcs_nss_supp_bw _320; } bw; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ieee80211_eht_mcs_nss_supp extends Union {
    public ieee80211_eht_mcs_nss_supp_20mhz_only only_20mhz;

    public bw_of_anon_member_of_ieee80211_eht_mcs_nss_supp bw;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct netlbl_domaddr_map *addrsel; struct cipso_v4_doi *cipso; struct calipso_doi *calipso; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_netlbl_dommap_def extends Union {
    public Ptr<netlbl_domaddr_map> addrsel;

    public Ptr<cipso_v4_doi> cipso;

    public Ptr<calipso_doi> calipso;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 bytes[16]; short unsigned int words[8]; unsigned int dwords[4]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_ncsi_cmd_arg extends Union {
    public char @Size(16) [] bytes;

    public @Unsigned short @Size(8) [] words;

    public @Unsigned int @Size(4) [] dwords;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int csum_start; short unsigned int csum_offset; long long unsigned int launch_time; } request; struct { long long unsigned int tx_timestamp; } completion; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_xsk_tx_metadata extends Union {
    public request_of_anon_member_of_xsk_tx_metadata request;

    public completion_of_anon_member_of_xsk_tx_metadata completion;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int suboptions; short unsigned int use_map; short unsigned int dsn64; short unsigned int data_fin; short unsigned int use_ack; short unsigned int ack64; short unsigned int mpc_map; short unsigned int reset_reason; short unsigned int reset_transient; short unsigned int echo; short unsigned int backup; short unsigned int deny_join_id0; short unsigned int __unused; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_mptcp_options_received_and_status_of_anon_member_of_mptcp_options_received extends Struct {
    public @Unsigned short suboptions;

    public @Unsigned short use_map;

    public @Unsigned short dsn64;

    public @Unsigned short data_fin;

    public @Unsigned short use_ack;

    public @Unsigned short ack64;

    public @Unsigned short mpc_map;

    public @Unsigned short reset_reason;

    public @Unsigned short reset_transient;

    public @Unsigned short echo;

    public @Unsigned short backup;

    public @Unsigned short deny_join_id0;

    public @Unsigned short __unused;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { short unsigned int suboptions; short unsigned int use_map; short unsigned int dsn64; short unsigned int data_fin; short unsigned int use_ack; short unsigned int ack64; short unsigned int mpc_map; short unsigned int reset_reason; short unsigned int reset_transient; short unsigned int echo; short unsigned int backup; short unsigned int deny_join_id0; short unsigned int __unused; }; struct { short unsigned int suboptions; short unsigned int use_map; short unsigned int dsn64; short unsigned int data_fin; short unsigned int use_ack; short unsigned int ack64; short unsigned int mpc_map; short unsigned int reset_reason; short unsigned int reset_transient; short unsigned int echo; short unsigned int backup; short unsigned int deny_join_id0; short unsigned int __unused; } status; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mptcp_options_received extends Union {
    public anon_member_of_anon_member_of_mptcp_options_received_and_status_of_anon_member_of_mptcp_options_received anon0;

    public anon_member_of_anon_member_of_mptcp_options_received_and_status_of_anon_member_of_mptcp_options_received status;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { u8 addr_signal; _Bool server_side; _Bool work_pending; _Bool accept_addr; _Bool accept_subflow; _Bool remote_deny_join_id0; u8 add_addr_signaled; u8 add_addr_accepted; u8 local_addr_used; u8 pm_type; u8 subflows; u8 status; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_mptcp_pm_data_and_reset_of_anon_member_of_mptcp_pm_data extends Struct {
    public char addr_signal;

    public boolean server_side;

    public boolean work_pending;

    public boolean accept_addr;

    public boolean accept_subflow;

    public boolean remote_deny_join_id0;

    public char add_addr_signaled;

    public char add_addr_accepted;

    public char local_addr_used;

    public char pm_type;

    public char subflows;

    public char status;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { u8 addr_signal; _Bool server_side; _Bool work_pending; _Bool accept_addr; _Bool accept_subflow; _Bool remote_deny_join_id0; u8 add_addr_signaled; u8 add_addr_accepted; u8 local_addr_used; u8 pm_type; u8 subflows; u8 status; }; struct { u8 addr_signal; _Bool server_side; _Bool work_pending; _Bool accept_addr; _Bool accept_subflow; _Bool remote_deny_join_id0; u8 add_addr_signaled; u8 add_addr_accepted; u8 local_addr_used; u8 pm_type; u8 subflows; u8 status; } reset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mptcp_pm_data extends Union {
    public anon_member_of_anon_member_of_mptcp_pm_data_and_reset_of_anon_member_of_mptcp_pm_data anon0;

    public anon_member_of_anon_member_of_mptcp_pm_data_and_reset_of_anon_member_of_mptcp_pm_data reset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { u8 hmac[20]; long long unsigned int iasn; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_anon_member_of_mptcp_subflow_context_and_reset_of_anon_member_of_mptcp_subflow_context extends Union {
    public char @Size(20) [] hmac;

    public @Unsigned long iasn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int avg_pacing_rate; long long unsigned int local_key; long long unsigned int remote_key; long long unsigned int idsn; long long unsigned int map_seq; long long unsigned int rcv_wnd_sent; unsigned int snd_isn; unsigned int token; unsigned int rel_write_seq; unsigned int map_subflow_seq; unsigned int ssn_offset; unsigned int map_data_len; unsigned int map_data_csum; unsigned int map_csum_len; unsigned int request_mptcp; unsigned int request_join; unsigned int request_bkup; unsigned int mp_capable; unsigned int mp_join; unsigned int pm_notified; unsigned int conn_finished; unsigned int map_valid; unsigned int map_csum_reqd; unsigned int map_data_fin; unsigned int mpc_map; unsigned int backup; unsigned int send_mp_prio; unsigned int send_mp_fail; unsigned int send_fastclose; unsigned int send_infinite_map; unsigned int remote_key_valid; unsigned int disposable; unsigned int stale; unsigned int valid_csum_seen; unsigned int is_mptfo; unsigned int close_event_done; unsigned int mpc_drop; unsigned int __unused; _Bool data_avail; _Bool scheduled; _Bool pm_listener; _Bool fully_established; unsigned int remote_nonce; long long unsigned int thmac; unsigned int local_nonce; unsigned int remote_token; union { u8 hmac[20]; long long unsigned int iasn; }; short int local_id; u8 remote_id; u8 reset_seen; u8 reset_transient; u8 reset_reason; u8 stale_count; unsigned int subflow_id; long int delegated_status; long unsigned int fail_tout; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_mptcp_subflow_context_and_reset_of_anon_member_of_mptcp_subflow_context extends Struct {
    public @Unsigned long avg_pacing_rate;

    public @Unsigned long local_key;

    public @Unsigned long remote_key;

    public @Unsigned long idsn;

    public @Unsigned long map_seq;

    public @Unsigned long rcv_wnd_sent;

    public @Unsigned int snd_isn;

    public @Unsigned int token;

    public @Unsigned int rel_write_seq;

    public @Unsigned int map_subflow_seq;

    public @Unsigned int ssn_offset;

    public @Unsigned int map_data_len;

    public @Unsigned @OriginalName("__wsum") int map_data_csum;

    public @Unsigned int map_csum_len;

    public @Unsigned int request_mptcp;

    public @Unsigned int request_join;

    public @Unsigned int request_bkup;

    public @Unsigned int mp_capable;

    public @Unsigned int mp_join;

    public @Unsigned int pm_notified;

    public @Unsigned int conn_finished;

    public @Unsigned int map_valid;

    public @Unsigned int map_csum_reqd;

    public @Unsigned int map_data_fin;

    public @Unsigned int mpc_map;

    public @Unsigned int backup;

    public @Unsigned int send_mp_prio;

    public @Unsigned int send_mp_fail;

    public @Unsigned int send_fastclose;

    public @Unsigned int send_infinite_map;

    public @Unsigned int remote_key_valid;

    public @Unsigned int disposable;

    public @Unsigned int stale;

    public @Unsigned int valid_csum_seen;

    public @Unsigned int is_mptfo;

    public @Unsigned int close_event_done;

    public @Unsigned int mpc_drop;

    public @Unsigned int __unused;

    public boolean data_avail;

    public boolean scheduled;

    public boolean pm_listener;

    public boolean fully_established;

    public @Unsigned int remote_nonce;

    public @Unsigned long thmac;

    public @Unsigned int local_nonce;

    public @Unsigned int remote_token;

    @InlineUnion(64973)
    public char @Size(20) [] hmac;

    @InlineUnion(64973)
    public @Unsigned long iasn;

    public short local_id;

    public char remote_id;

    public char reset_seen;

    public char reset_transient;

    public char reset_reason;

    public char stale_count;

    public @Unsigned int subflow_id;

    public long delegated_status;

    public @Unsigned long fail_tout;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { long unsigned int avg_pacing_rate; long long unsigned int local_key; long long unsigned int remote_key; long long unsigned int idsn; long long unsigned int map_seq; long long unsigned int rcv_wnd_sent; unsigned int snd_isn; unsigned int token; unsigned int rel_write_seq; unsigned int map_subflow_seq; unsigned int ssn_offset; unsigned int map_data_len; unsigned int map_data_csum; unsigned int map_csum_len; unsigned int request_mptcp; unsigned int request_join; unsigned int request_bkup; unsigned int mp_capable; unsigned int mp_join; unsigned int pm_notified; unsigned int conn_finished; unsigned int map_valid; unsigned int map_csum_reqd; unsigned int map_data_fin; unsigned int mpc_map; unsigned int backup; unsigned int send_mp_prio; unsigned int send_mp_fail; unsigned int send_fastclose; unsigned int send_infinite_map; unsigned int remote_key_valid; unsigned int disposable; unsigned int stale; unsigned int valid_csum_seen; unsigned int is_mptfo; unsigned int close_event_done; unsigned int mpc_drop; unsigned int __unused; _Bool data_avail; _Bool scheduled; _Bool pm_listener; _Bool fully_established; unsigned int remote_nonce; long long unsigned int thmac; unsigned int local_nonce; unsigned int remote_token; union { u8 hmac[20]; long long unsigned int iasn; }; short int local_id; u8 remote_id; u8 reset_seen; u8 reset_transient; u8 reset_reason; u8 stale_count; unsigned int subflow_id; long int delegated_status; long unsigned int fail_tout; }; struct { long unsigned int avg_pacing_rate; long long unsigned int local_key; long long unsigned int remote_key; long long unsigned int idsn; long long unsigned int map_seq; long long unsigned int rcv_wnd_sent; unsigned int snd_isn; unsigned int token; unsigned int rel_write_seq; unsigned int map_subflow_seq; unsigned int ssn_offset; unsigned int map_data_len; unsigned int map_data_csum; unsigned int map_csum_len; unsigned int request_mptcp; unsigned int request_join; unsigned int request_bkup; unsigned int mp_capable; unsigned int mp_join; unsigned int pm_notified; unsigned int conn_finished; unsigned int map_valid; unsigned int map_csum_reqd; unsigned int map_data_fin; unsigned int mpc_map; unsigned int backup; unsigned int send_mp_prio; unsigned int send_mp_fail; unsigned int send_fastclose; unsigned int send_infinite_map; unsigned int remote_key_valid; unsigned int disposable; unsigned int stale; unsigned int valid_csum_seen; unsigned int is_mptfo; unsigned int close_event_done; unsigned int mpc_drop; unsigned int __unused; _Bool data_avail; _Bool scheduled; _Bool pm_listener; _Bool fully_established; unsigned int remote_nonce; long long unsigned int thmac; unsigned int local_nonce; unsigned int remote_token; union { u8 hmac[20]; long long unsigned int iasn; }; short int local_id; u8 remote_id; u8 reset_seen; u8 reset_transient; u8 reset_reason; u8 stale_count; unsigned int subflow_id; long int delegated_status; long unsigned int fail_tout; } reset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mptcp_subflow_context extends Union {
    public anon_member_of_anon_member_of_mptcp_subflow_context_and_reset_of_anon_member_of_mptcp_subflow_context anon0;

    public anon_member_of_anon_member_of_mptcp_subflow_context_and_reset_of_anon_member_of_mptcp_subflow_context reset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { short unsigned int sa_family; struct sockaddr sa_local; struct sockaddr_in sin_local; struct sockaddr_in6 sin6_local; struct __kernel_sockaddr_storage ss_local; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mptcp_subflow_addrs extends Union {
    public @Unsigned @OriginalName("__kernel_sa_family_t") short sa_family;

    public sockaddr sa_local;

    public sockaddr_in sin_local;

    public sockaddr_in6 sin6_local;

    public __kernel_sockaddr_storage ss_local;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct mctp_dev *dev; struct mctp_fq_addr gateway; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_mctp_route extends Union {
    public Ptr<mctp_dev> dev;

    public mctp_fq_addr gateway;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct net_device *netdev; struct devlink *devlink; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_net_shaper_binding extends Union {
    public Ptr<net_device> netdev;

    public Ptr<devlink> devlink;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct file *file; struct folio *folio; void *addr; long long int folio_off; _Bool may_fault; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_freader extends Struct {
    public Ptr<file> file;

    public Ptr<folio> folio;

    public Ptr<?> addr;

    public @OriginalName("loff_t") long folio_off;

    public boolean may_fault;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { struct file *file; struct folio *folio; void *addr; long long int folio_off; _Bool may_fault; }; struct { const u8 *data; long long unsigned int data_sz; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_freader extends Union {
    public anon_member_of_anon_member_of_freader anon0;

    public anon_member_of_anon_member_of_freader anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { void* pad[15]; struct maple_metadata meta; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_maple_range_64 extends Struct {
    public Ptr<?> @Size(15) [] pad;

    public maple_metadata meta;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { void* slot[16]; struct { void* pad[15]; struct maple_metadata meta; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_maple_range_64 extends Union {
    public Ptr<?> @Size(16) [] slot;

    public anon_member_of_anon_member_of_maple_range_64 anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { maple_pnode *parent; void* slot[31]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_maple_node extends Struct {
    public @OriginalName("maple_pnode") Ptr<?> parent;

    public Ptr<?> @Size(31) [] slot;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { struct { maple_pnode *parent; void* slot[31]; }; struct { void *pad; struct callback_head rcu; maple_enode *piv_parent; u8 parent_slot; enum maple_type type; u8 slot_len; unsigned int ma_flags; }; struct maple_range_64 mr64; struct maple_arange_64 ma64; struct maple_alloc alloc; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_maple_node extends Union {
    public anon_member_of_anon_member_of_maple_node anon0;

    public anon_member_of_anon_member_of_maple_node anon1;

    public maple_range_64 mr64;

    public maple_arange_64 ma64;

    public maple_alloc alloc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int padding[21]; long unsigned int gap[21]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_anon_member_of_maple_big_node extends Struct {
    public @Unsigned long @Size(21) [] padding;

    public @Unsigned long @Size(21) [] gap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { maple_enode* slot[34]; struct { long unsigned int padding[21]; long unsigned int gap[21]; }; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class anon_member_of_maple_big_node extends Union {
    public @OriginalName("maple_enode") Ptr<?> @Size(34) [] slot;

    public anon_member_of_anon_member_of_maple_big_node anon1;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union __sifields"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class __sifields extends Union {
    public _kill_of___sifields _kill;

    public _timer_of___sifields _timer;

    public _rt_of___sifields _rt;

    public _sigchld_of___sifields _sigchld;

    public _sigfault_of___sifields _sigfault;

    public _sigpoll_of___sifields _sigpoll;

    public _sigsys_of___sifields _sigsys;
  }
}
