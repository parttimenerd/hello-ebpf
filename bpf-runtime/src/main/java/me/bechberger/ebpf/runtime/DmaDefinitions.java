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
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
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
 * Generated class for BPF runtime types that start with dma
 */
@java.lang.SuppressWarnings("unused")
public final class DmaDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__dma_alloc_from_pool($arg1, $arg2, $arg3, $arg4, (_Bool (*)(struct device*, long long unsigned int, long unsigned int))$arg5)")
  public static Ptr<page> __dma_alloc_from_pool(Ptr<device> dev, @Unsigned long size,
      Ptr<gen_pool> pool, Ptr<Ptr<?>> cpu_addr, Ptr<?> phys_addr_ok) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> __dma_alloc_pages(Ptr<device> dev, @Unsigned long size,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> dma_handle, dma_data_direction dir,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__dma_async_device_channel_register($arg1, $arg2, (const u8 *)$arg3)")
  public static int __dma_async_device_channel_register(Ptr<dma_device> device, Ptr<dma_chan> chan,
      String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __dma_async_device_channel_unregister(Ptr<dma_device> device,
      Ptr<dma_chan> chan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<gen_pool> __dma_atomic_pool_init(@Unsigned long pool_size,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> __dma_direct_alloc_pages(Ptr<device> dev, @Unsigned long size,
      @Unsigned @OriginalName("gfp_t") int gfp, boolean allow_highmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __dma_fence_enable_signaling(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> __dma_fence_unwrap_merge(@Unsigned int num_fences,
      Ptr<Ptr<dma_fence>> fences, Ptr<dma_fence_unwrap> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __dma_free_pages(Ptr<device> dev, @Unsigned long size, Ptr<page> page,
      @Unsigned @OriginalName("dma_addr_t") long dma_handle, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __dma_map_cont(Ptr<device> dev, Ptr<scatterlist> start, int nelems,
      Ptr<scatterlist> sout, @Unsigned long pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __dma_map_sg_attrs(Ptr<device> dev, Ptr<scatterlist> sg, int nents,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __dma_need_sync(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__dma_request_channel((const struct {\n"
          + "  long unsigned int bits[1];\n"
          + "} *)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<dma_chan> __dma_request_channel(Ptr<dma_cap_mask_t> mask,
      @OriginalName("dma_filter_fn") Ptr<?> fn, Ptr<?> fn_param, Ptr<device_node> np) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __dma_rx_complete(Ptr<uart_8250_port> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __dma_sync_sg_for_cpu(Ptr<device> dev, Ptr<scatterlist> sg, int nelems,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __dma_sync_sg_for_device(Ptr<device> dev, Ptr<scatterlist> sg, int nelems,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __dma_sync_single_for_cpu(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __dma_sync_single_for_device(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __dma_tx_complete(Ptr<?> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_addressing_limited(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> dma_alloc_attrs(Ptr<device> dev, @Unsigned long size,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> dma_handle,
      @Unsigned @OriginalName("gfp_t") int flag, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> dma_alloc_contiguous(Ptr<device> dev, @Unsigned long size,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> dma_alloc_from_contiguous(Ptr<device> dev, @Unsigned long count,
      @Unsigned int align, boolean no_warn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_alloc_from_pool($arg1, $arg2, $arg3, $arg4, (_Bool (*)(struct device*, long long unsigned int, long unsigned int))$arg5)")
  public static Ptr<page> dma_alloc_from_pool(Ptr<device> dev, @Unsigned long size,
      Ptr<Ptr<?>> cpu_addr, @Unsigned @OriginalName("gfp_t") int gfp, Ptr<?> phys_addr_ok) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> dma_alloc_noncontiguous(Ptr<device> dev, @Unsigned long size,
      dma_data_direction dir, @Unsigned @OriginalName("gfp_t") int gfp, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> dma_alloc_pages(Ptr<device> dev, @Unsigned long size,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> dma_handle, dma_data_direction dir,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_async_device_channel_register($arg1, $arg2, (const u8 *)$arg3)")
  public static int dma_async_device_channel_register(Ptr<dma_device> device, Ptr<dma_chan> chan,
      String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_async_device_channel_unregister(Ptr<dma_device> device,
      Ptr<dma_chan> chan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_async_device_register(Ptr<dma_device> device) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_async_device_unregister(Ptr<dma_device> device) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_async_tx_descriptor_init(Ptr<dma_async_tx_descriptor> tx,
      Ptr<dma_chan> chan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_atomic_pool_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_buf_attachment> dma_buf_attach(Ptr<dma_buf> dmabuf, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_begin_cpu_access(Ptr<dma_buf> dmabuf, dma_data_direction direction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_debug_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_debug_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_deinit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_detach(Ptr<dma_buf> dmabuf, Ptr<dma_buf_attachment> attach) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_buf_dynamic_attach($arg1, $arg2, (const struct dma_buf_attach_ops *)$arg3, $arg4)")
  public static Ptr<dma_buf_attachment> dma_buf_dynamic_attach(Ptr<dma_buf> dmabuf, Ptr<device> dev,
      Ptr<dma_buf_attach_ops> importer_ops, Ptr<?> importer_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_end_cpu_access(Ptr<dma_buf> dmabuf, dma_data_direction direction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_buf_export((const struct dma_buf_export_info *)$arg1)")
  public static Ptr<dma_buf> dma_buf_export(Ptr<dma_buf_export_info> exp_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_fd(Ptr<dma_buf> dmabuf, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_file_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_fs_init_context(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_buf> dma_buf_get(int fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long dma_buf_ioctl(Ptr<file> file, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_buf> dma_buf_iter_begin() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_buf> dma_buf_iter_next(Ptr<dma_buf> dmabuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("loff_t") long dma_buf_llseek(Ptr<file> file,
      @OriginalName("loff_t") long offset, int whence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> dma_buf_map_attachment(Ptr<dma_buf_attachment> attach,
      dma_data_direction direction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> dma_buf_map_attachment_unlocked(Ptr<dma_buf_attachment> attach,
      dma_data_direction direction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_mmap(Ptr<dma_buf> dmabuf, Ptr<vm_area_struct> vma,
      @Unsigned long pgoff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_mmap_internal(Ptr<file> file, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_move_notify(Ptr<dma_buf> dmabuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_pin(Ptr<dma_buf_attachment> attach) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int dma_buf_poll(Ptr<file> file,
      Ptr<poll_table_struct> poll) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_buf_poll_add_cb(Ptr<dma_resv> resv, boolean write,
      Ptr<dma_buf_poll_cb_t> dcb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_poll_cb(Ptr<dma_fence> fence, Ptr<dma_fence_cb> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_put(Ptr<dma_buf> dmabuf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_release(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_show_fdinfo(Ptr<seq_file> m, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_unmap_attachment(Ptr<dma_buf_attachment> attach,
      Ptr<sg_table> sg_table, dma_data_direction direction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_unmap_attachment_unlocked(Ptr<dma_buf_attachment> attach,
      Ptr<sg_table> sg_table, dma_data_direction direction) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_unpin(Ptr<dma_buf_attachment> attach) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_vmap(Ptr<dma_buf> dmabuf, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_buf_vmap_unlocked(Ptr<dma_buf> dmabuf, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_vunmap(Ptr<dma_buf> dmabuf, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_buf_vunmap_unlocked(Ptr<dma_buf> dmabuf, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_bus_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_can_mmap(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_chan_get(Ptr<dma_chan> chan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_chan_put(Ptr<dma_chan> chan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_channel_rebalance() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_channel_table_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_coherent_ok(Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> dma_common_alloc_pages(Ptr<device> dev, @Unsigned long size,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> dma_handle, dma_data_direction dir,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_common_contiguous_remap($arg1, $arg2, $arg3, (const void *)$arg4)")
  public static Ptr<?> dma_common_contiguous_remap(Ptr<page> page, @Unsigned long size,
      @OriginalName("pgprot_t") pgprot prot, Ptr<?> caller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Ptr<page>> dma_common_find_pages(Ptr<?> cpu_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_common_free_pages(Ptr<device> dev, @Unsigned long size, Ptr<page> page,
      @Unsigned @OriginalName("dma_addr_t") long dma_handle, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_common_free_remap(Ptr<?> cpu_addr, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_common_get_sgtable(Ptr<device> dev, Ptr<sg_table> sgt, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_common_mmap(Ptr<device> dev, Ptr<vm_area_struct> vma, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_common_pages_remap($arg1, $arg2, $arg3, (const void *)$arg4)")
  public static Ptr<?> dma_common_pages_remap(Ptr<Ptr<page>> pages, @Unsigned long size,
      @OriginalName("pgprot_t") pgprot prot, Ptr<?> caller) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> dma_common_vaddr_to_page(Ptr<?> cpu_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_contiguous_early_fixup(@Unsigned @OriginalName("phys_addr_t") long base,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_contiguous_reserve(@Unsigned @OriginalName("phys_addr_t") long limit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_contiguous_reserve_area(@Unsigned @OriginalName("phys_addr_t") long size,
      @Unsigned @OriginalName("phys_addr_t") long base,
      @Unsigned @OriginalName("phys_addr_t") long limit, Ptr<Ptr<cma>> res_cma, boolean fixed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_direct_all_ram_mapped(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> dma_direct_alloc(Ptr<device> dev, @Unsigned long size,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> dma_handle,
      @Unsigned @OriginalName("gfp_t") int gfp, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> dma_direct_alloc_from_pool(Ptr<device> dev, @Unsigned long size,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> dma_handle,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> dma_direct_alloc_pages(Ptr<device> dev, @Unsigned long size,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> dma_handle, dma_data_direction dir,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_direct_can_mmap(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_direct_free(Ptr<device> dev, @Unsigned long size, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_direct_free_pages(Ptr<device> dev, @Unsigned long size, Ptr<page> page,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long dma_direct_get_required_mask(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_direct_get_sgtable(Ptr<device> dev, Ptr<sg_table> sgt, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long dma_direct_map_page(Ptr<device> dev,
      Ptr<page> page, @Unsigned long offset, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long dma_direct_map_resource(Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long paddr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_direct_map_sg(Ptr<device> dev, Ptr<scatterlist> sgl, int nents,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long dma_direct_max_mapping_size(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_direct_mmap(Ptr<device> dev, Ptr<vm_area_struct> vma, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_direct_need_sync(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_direct_set_offset(Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long cpu_start,
      @Unsigned @OriginalName("dma_addr_t") long dma_start, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_direct_supported(Ptr<device> dev, @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_direct_sync_sg_for_cpu(Ptr<device> dev, Ptr<scatterlist> sgl, int nents,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_direct_sync_sg_for_device(Ptr<device> dev, Ptr<scatterlist> sgl, int nents,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_direct_unmap_sg(Ptr<device> dev, Ptr<scatterlist> sgl, int nents,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long dma_dummy_map_page(Ptr<device> dev,
      Ptr<page> page, @Unsigned long offset, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_dummy_map_sg(Ptr<device> dev, Ptr<scatterlist> sgl, int nelems,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_dummy_mmap(Ptr<device> dev, Ptr<vm_area_struct> vma, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_dummy_supported(Ptr<device> hwdev, @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_dummy_unmap_page(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long dma_handle, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_dummy_unmap_sg(Ptr<device> dev, Ptr<scatterlist> sgl, int nelems,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_fence_add_callback(Ptr<dma_fence> fence, Ptr<dma_fence_cb> cb,
      @OriginalName("dma_fence_func_t") Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_fence_allocate_private_stub(
      @OriginalName("ktime_t") long timestamp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence_array> dma_fence_array_alloc(int num_fences) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_array_cb_func(Ptr<dma_fence> f, Ptr<dma_fence_cb> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence_array> dma_fence_array_create(int num_fences,
      Ptr<Ptr<dma_fence>> fences, @Unsigned long context, @Unsigned int seqno,
      boolean signal_on_any) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_fence_array_enable_signaling(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_fence_array_first(Ptr<dma_fence> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)dma_fence_array_get_driver_name($arg1))")
  public static String dma_fence_array_get_driver_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)dma_fence_array_get_timeline_name($arg1))")
  public static String dma_fence_array_get_timeline_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_array_init(Ptr<dma_fence_array> array, int num_fences,
      Ptr<Ptr<dma_fence>> fences, @Unsigned long context, @Unsigned int seqno,
      boolean signal_on_any) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_fence_array_next(Ptr<dma_fence> head, @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_array_release(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_array_set_deadline(Ptr<dma_fence> fence,
      @OriginalName("ktime_t") long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_fence_array_signaled(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_chain_cb(Ptr<dma_fence> f, Ptr<dma_fence_cb> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_fence_chain_enable_signaling(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_fence_chain_find_seqno(Ptr<Ptr<dma_fence>> pfence,
      @Unsigned @OriginalName("uint64_t") long seqno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)dma_fence_chain_get_driver_name($arg1))")
  public static String dma_fence_chain_get_driver_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)dma_fence_chain_get_timeline_name($arg1))")
  public static String dma_fence_chain_get_timeline_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_chain_init(Ptr<dma_fence_chain> chain, Ptr<dma_fence> prev,
      Ptr<dma_fence> fence, @Unsigned @OriginalName("uint64_t") long seqno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_chain_irq_work(Ptr<irq_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_chain_release(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_chain_set_deadline(Ptr<dma_fence> fence,
      @OriginalName("ktime_t") long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_fence_chain_signaled(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_fence_chain_walk(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long dma_fence_context_alloc(@Unsigned int num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_fence_dedup_array(Ptr<Ptr<dma_fence>> fences, int num_fences) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long dma_fence_default_wait(Ptr<dma_fence> fence, boolean intr, long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_default_wait_cb(Ptr<dma_fence> fence, Ptr<dma_fence_cb> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_describe(Ptr<dma_fence> fence, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)dma_fence_driver_name($arg1))")
  public static String dma_fence_driver_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_enable_sw_signaling(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_free(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_fence_get_status(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_fence_get_stub() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_fence_init($arg1, (const struct dma_fence_ops *)$arg2, $arg3, $arg4, $arg5)")
  public static void dma_fence_init(Ptr<dma_fence> fence, Ptr<dma_fence_ops> ops,
      Ptr<@OriginalName("spinlock_t") spinlock> lock, @Unsigned long context,
      @Unsigned long seqno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_fence_init64($arg1, (const struct dma_fence_ops *)$arg2, $arg3, $arg4, $arg5)")
  public static void dma_fence_init64(Ptr<dma_fence> fence, Ptr<dma_fence_ops> ops,
      Ptr<@OriginalName("spinlock_t") spinlock> lock, @Unsigned long context,
      @Unsigned long seqno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_fence_match_context(Ptr<dma_fence> fence, @Unsigned long context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_release(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_fence_remove_callback(Ptr<dma_fence> fence, Ptr<dma_fence_cb> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_fence_set_deadline(Ptr<dma_fence> fence,
      @OriginalName("ktime_t") long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_fence_signal(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_fence_signal_locked(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_fence_signal_timestamp(Ptr<dma_fence> fence,
      @OriginalName("ktime_t") long timestamp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_fence_signal_timestamp_locked(Ptr<dma_fence> fence,
      @OriginalName("ktime_t") long timestamp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)dma_fence_stub_get_name($arg1))")
  public static String dma_fence_stub_get_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)dma_fence_timeline_name($arg1))")
  public static String dma_fence_timeline_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_fence_unwrap_first(Ptr<dma_fence> head,
      Ptr<dma_fence_unwrap> cursor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_fence_unwrap_next(Ptr<dma_fence_unwrap> cursor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long dma_fence_wait_any_timeout(Ptr<Ptr<dma_fence>> fences,
      @Unsigned @OriginalName("uint32_t") int count, boolean intr, long timeout,
      Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long dma_fence_wait_timeout(Ptr<dma_fence> fence, boolean intr, long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_chan> dma_find_channel(dma_transaction_type tx_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_flags(Ptr<pnp_dev> dev, int type, int bus_master, int transfer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_free_attrs(Ptr<device> dev, @Unsigned long size, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_handle, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_free_contiguous(Ptr<device> dev, Ptr<page> page, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_free_desc_resource(Ptr<virt_dma_desc> vdesc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_free_from_pool(Ptr<device> dev, Ptr<?> start, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_free_noncontiguous(Ptr<device> dev, @Unsigned long size, Ptr<sg_table> sgt,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_free_pages(Ptr<device> dev, @Unsigned long size, Ptr<page> page,
      @Unsigned @OriginalName("dma_addr_t") long dma_handle, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_chan> dma_get_any_slave_channel(Ptr<dma_device> device) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long dma_get_merge_boundary(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long dma_get_required_mask(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_get_sgtable_attrs(Ptr<device> dev, Ptr<sg_table> sgt, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_get_slave_caps(Ptr<dma_chan> chan, Ptr<dma_slave_caps> caps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_chan> dma_get_slave_channel(Ptr<dma_chan> chan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_heap_add((const struct dma_heap_export_info *)$arg1)")
  public static Ptr<dma_heap> dma_heap_add(Ptr<dma_heap_export_info> exp_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_heap_devnode((const struct device *)$arg1, $arg2)")
  public static String dma_heap_devnode(Ptr<device> dev,
      Ptr<java.lang. @Unsigned @OriginalName("umode_t") Short> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> dma_heap_get_drvdata(Ptr<dma_heap> heap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)dma_heap_get_name($arg1))")
  public static String dma_heap_get_name(Ptr<dma_heap> heap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_heap_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long dma_heap_ioctl(Ptr<file> file, @Unsigned int ucmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_heap_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn dma_interrupt(int irq, Ptr<?> dev_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_iova_destroy(Ptr<device> dev, Ptr<dma_iova_state> state,
      @Unsigned long mapped_len, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_iova_free(Ptr<device> dev, Ptr<dma_iova_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_iova_link(Ptr<device> dev, Ptr<dma_iova_state> state,
      @Unsigned @OriginalName("phys_addr_t") long phys, @Unsigned long offset, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_iova_sync(Ptr<device> dev, Ptr<dma_iova_state> state, @Unsigned long offset,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_iova_try_alloc(Ptr<device> dev, Ptr<dma_iova_state> state,
      @Unsigned @OriginalName("phys_addr_t") long phys, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_iova_unlink(Ptr<device> dev, Ptr<dma_iova_state> state,
      @Unsigned long offset, @Unsigned long size, dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_issue_pending_all() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long dma_map_page_attrs(Ptr<device> dev,
      Ptr<page> page, @Unsigned long offset, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long dma_map_resource(Ptr<device> dev,
      @Unsigned @OriginalName("phys_addr_t") long phys_addr, @Unsigned long size,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int dma_map_sg_attrs(Ptr<device> dev, Ptr<scatterlist> sg, int nents,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_map_sgtable(Ptr<device> dev, Ptr<sg_table> sgt, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long dma_mask_bits_show(Ptr<device> dev,
      Ptr<device_attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long dma_max_mapping_size(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_mmap_attrs(Ptr<device> dev, Ptr<vm_area_struct> vma, Ptr<?> cpu_addr,
      @Unsigned @OriginalName("dma_addr_t") long dma_addr, @Unsigned long size,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_mmap_noncontiguous(Ptr<device> dev, Ptr<vm_area_struct> vma,
      @Unsigned long size, Ptr<sg_table> sgt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_mmap_pages(Ptr<device> dev, Ptr<vm_area_struct> vma, @Unsigned long size,
      Ptr<page> page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_need_unmap(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_numa_cma_reserve() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long dma_opt_mapping_size(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_pci_p2pdma_supported(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("pgprot_t") pgprot dma_pgprot(Ptr<device> dev,
      @OriginalName("pgprot_t") pgprot prot, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> dma_pool_alloc(Ptr<dma_pool> pool,
      @Unsigned @OriginalName("gfp_t") int mem_flags,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_pool_create_node((const u8 *)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static Ptr<dma_pool> dma_pool_create_node(String name, Ptr<device> dev,
      @Unsigned long size, @Unsigned long align, @Unsigned long boundary, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_pool_destroy(Ptr<dma_pool> pool) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_pool_free(Ptr<dma_pool> pool, Ptr<?> vaddr,
      @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_pte_clear_level(Ptr<dmar_domain> domain, int level, Ptr<dma_pte> pte,
      @Unsigned long pfn, @Unsigned long start_pfn, @Unsigned long last_pfn,
      Ptr<iommu_pages_list> freelist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_pte_clear_range(Ptr<dmar_domain> domain, @Unsigned long start_pfn,
      @Unsigned long last_pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_pte_free_level(Ptr<dmar_domain> domain, int level, int retain_level,
      Ptr<dma_pte> pte, @Unsigned long pfn, @Unsigned long start_pfn, @Unsigned long last_pfn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_release_channel(Ptr<dma_chan> chan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_release_from_contiguous(Ptr<device> dev, Ptr<page> pages, int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_request_chan($arg1, (const u8 *)$arg2)")
  public static Ptr<dma_chan> dma_request_chan(Ptr<device> dev, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("dma_request_chan_by_mask((const struct {\n"
          + "  long unsigned int bits[1];\n"
          + "} *)$arg1)")
  public static Ptr<dma_chan> dma_request_chan_by_mask(Ptr<dma_cap_mask_t> mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_resv_add_fence(Ptr<dma_resv> obj, Ptr<dma_fence> fence,
      dma_resv_usage usage) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_resv_copy_fences(Ptr<dma_resv> dst, Ptr<dma_resv> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_resv_describe(Ptr<dma_resv> obj, Ptr<seq_file> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_resv_fini(Ptr<dma_resv> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_resv_get_fences(Ptr<dma_resv> obj, dma_resv_usage usage,
      Ptr<java.lang. @Unsigned Integer> num_fences, Ptr<Ptr<Ptr<dma_fence>>> fences) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_resv_get_singleton(Ptr<dma_resv> obj, dma_resv_usage usage,
      Ptr<Ptr<dma_fence>> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_resv_init(Ptr<dma_resv> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_resv_iter_first(Ptr<dma_resv_iter> cursor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_resv_iter_first_unlocked(Ptr<dma_resv_iter> cursor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_resv_iter_next(Ptr<dma_resv_iter> cursor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> dma_resv_iter_next_unlocked(Ptr<dma_resv_iter> cursor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_resv_iter_walk_unlocked(Ptr<dma_resv_iter> cursor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_resv_list> dma_resv_list_alloc(@Unsigned int max_fences) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_resv_list_free(Ptr<dma_resv_list> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_resv_replace_fences(Ptr<dma_resv> obj,
      @Unsigned @OriginalName("uint64_t") long context, Ptr<dma_fence> replacement,
      dma_resv_usage usage) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_resv_reserve_fences(Ptr<dma_resv> obj, @Unsigned int num_fences) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_resv_set_deadline(Ptr<dma_resv> obj, dma_resv_usage usage,
      @OriginalName("ktime_t") long deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean dma_resv_test_signaled(Ptr<dma_resv> obj, dma_resv_usage usage) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long dma_resv_wait_timeout(Ptr<dma_resv> obj, dma_resv_usage usage, boolean intr,
      @Unsigned long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_run_dependencies(Ptr<dma_async_tx_descriptor> tx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_rx_complete(Ptr<?> param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_set_coherent_mask(Ptr<device> dev, @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int dma_set_mask(Ptr<device> dev, @Unsigned long mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static dma_status dma_sync_wait(Ptr<dma_chan> chan,
      @OriginalName("dma_cookie_t") int cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_unmap_page_attrs(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_unmap_resource(Ptr<device> dev,
      @Unsigned @OriginalName("dma_addr_t") long addr, @Unsigned long size, dma_data_direction dir,
      @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_unmap_sg_attrs(Ptr<device> dev, Ptr<scatterlist> sg, int nents,
      dma_data_direction dir, @Unsigned long attrs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> dma_vmap_noncontiguous(Ptr<device> dev, @Unsigned long size,
      Ptr<sg_table> sgt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_vunmap_noncontiguous(Ptr<device> dev, Ptr<?> vaddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static dma_status dma_wait_for_async_tx(Ptr<dma_async_tx_descriptor> tx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void dma_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_map_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_map_ops extends Struct {
    public Ptr<?> alloc;

    public Ptr<?> free;

    public Ptr<?> alloc_pages_op;

    public Ptr<?> free_pages;

    public Ptr<?> mmap;

    public Ptr<?> get_sgtable;

    public Ptr<?> map_page;

    public Ptr<?> unmap_page;

    public Ptr<?> map_sg;

    public Ptr<?> unmap_sg;

    public Ptr<?> map_resource;

    public Ptr<?> unmap_resource;

    public Ptr<?> sync_single_for_cpu;

    public Ptr<?> sync_single_for_device;

    public Ptr<?> sync_sg_for_cpu;

    public Ptr<?> sync_sg_for_device;

    public Ptr<?> cache_sync;

    public Ptr<?> dma_supported;

    public Ptr<?> get_required_mask;

    public Ptr<?> max_mapping_size;

    public Ptr<?> opt_mapping_size;

    public Ptr<?> get_merge_boundary;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_data_direction"
  )
  public enum dma_data_direction implements Enum<dma_data_direction>, TypedEnum<dma_data_direction, java.lang. @Unsigned Integer> {
    /**
     * {@code DMA_BIDIRECTIONAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DMA_BIDIRECTIONAL"
    )
    DMA_BIDIRECTIONAL,

    /**
     * {@code DMA_TO_DEVICE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DMA_TO_DEVICE"
    )
    DMA_TO_DEVICE,

    /**
     * {@code DMA_FROM_DEVICE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DMA_FROM_DEVICE"
    )
    DMA_FROM_DEVICE,

    /**
     * {@code DMA_NONE = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DMA_NONE"
    )
    DMA_NONE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_devres"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_devres extends Struct {
    public @Unsigned long size;

    public Ptr<?> vaddr;

    public @Unsigned @OriginalName("dma_addr_t") long dma_handle;

    public @Unsigned long attrs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_chan"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_chan extends Struct {
    public int lock;

    public String device_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_fence"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_fence extends Struct {
    public Ptr<@OriginalName("spinlock_t") spinlock> lock;

    public Ptr<dma_fence_ops> ops;

    @InlineUnion(18153)
    public list_head cb_list;

    @InlineUnion(18153)
    public @OriginalName("ktime_t") long timestamp;

    @InlineUnion(18153)
    public callback_head rcu;

    public @Unsigned long context;

    public @Unsigned long seqno;

    public @Unsigned long flags;

    public kref refcount;

    public int error;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_fence_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_fence_ops extends Struct {
    public Ptr<?> get_driver_name;

    public Ptr<?> get_timeline_name;

    public Ptr<?> enable_signaling;

    public Ptr<?> signaled;

    public Ptr<?> wait;

    public Ptr<?> release;

    public Ptr<?> set_deadline;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_fence_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_fence_cb extends Struct {
    public list_head node;

    public @OriginalName("dma_fence_func_t") Ptr<?> func;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_buf_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_buf_ops extends Struct {
    public Ptr<?> attach;

    public Ptr<?> detach;

    public Ptr<?> pin;

    public Ptr<?> unpin;

    public Ptr<?> map_dma_buf;

    public Ptr<?> unmap_dma_buf;

    public Ptr<?> release;

    public Ptr<?> begin_cpu_access;

    public Ptr<?> end_cpu_access;

    public Ptr<?> mmap;

    public Ptr<?> vmap;

    public Ptr<?> vunmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_buf"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_buf extends Struct {
    public @Unsigned long size;

    public Ptr<file> file;

    public list_head attachments;

    public Ptr<dma_buf_ops> ops;

    public @Unsigned int vmapping_counter;

    public iosys_map vmap_ptr;

    public String exp_name;

    public String name;

    public @OriginalName("spinlock_t") spinlock name_lock;

    public Ptr<module> owner;

    public list_head list_node;

    public Ptr<?> priv;

    public Ptr<dma_resv> resv;

    public @OriginalName("wait_queue_head_t") wait_queue_head poll;

    public dma_buf_poll_cb_t cb_in;

    public dma_buf_poll_cb_t cb_out;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_buf_attachment"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_buf_attachment extends Struct {
    public Ptr<dma_buf> dmabuf;

    public Ptr<device> dev;

    public list_head node;

    public boolean peer2peer;

    public Ptr<dma_buf_attach_ops> importer_ops;

    public Ptr<?> importer_priv;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_buf_poll_cb_t"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_buf_poll_cb_t extends Struct {
    public dma_fence_cb cb;

    public Ptr<@OriginalName("wait_queue_head_t") wait_queue_head> poll;

    public @Unsigned @OriginalName("__poll_t") int active;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_buf_attach_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_buf_attach_ops extends Struct {
    public boolean allow_peer2peer;

    public Ptr<?> move_notify;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_block"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_block extends Struct {
    public Ptr<dma_block> next_block;

    public @Unsigned @OriginalName("dma_addr_t") long dma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_pool"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_pool extends Struct {
    public list_head page_list;

    public @OriginalName("spinlock_t") spinlock lock;

    public Ptr<dma_block> next_block;

    public @Unsigned long nr_blocks;

    public @Unsigned long nr_active;

    public @Unsigned long nr_pages;

    public Ptr<device> dev;

    public @Unsigned int size;

    public @Unsigned int allocation;

    public @Unsigned int boundary;

    public int node;

    public char @Size(32) [] name;

    public list_head pools;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_page"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_page extends Struct {
    public list_head page_list;

    public Ptr<?> vaddr;

    public @Unsigned @OriginalName("dma_addr_t") long dma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_iova_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_iova_state extends Struct {
    public @Unsigned @OriginalName("dma_addr_t") long addr;

    public @Unsigned long __size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_resv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_resv extends Struct {
    public ww_mutex lock;

    public Ptr<dma_resv_list> fences;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_transaction_type"
  )
  public enum dma_transaction_type implements Enum<dma_transaction_type>, TypedEnum<dma_transaction_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DMA_MEMCPY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DMA_MEMCPY"
    )
    DMA_MEMCPY,

    /**
     * {@code DMA_XOR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DMA_XOR"
    )
    DMA_XOR,

    /**
     * {@code DMA_PQ = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DMA_PQ"
    )
    DMA_PQ,

    /**
     * {@code DMA_XOR_VAL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DMA_XOR_VAL"
    )
    DMA_XOR_VAL,

    /**
     * {@code DMA_PQ_VAL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DMA_PQ_VAL"
    )
    DMA_PQ_VAL,

    /**
     * {@code DMA_MEMSET = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DMA_MEMSET"
    )
    DMA_MEMSET,

    /**
     * {@code DMA_MEMSET_SG = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DMA_MEMSET_SG"
    )
    DMA_MEMSET_SG,

    /**
     * {@code DMA_INTERRUPT = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DMA_INTERRUPT"
    )
    DMA_INTERRUPT,

    /**
     * {@code DMA_PRIVATE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DMA_PRIVATE"
    )
    DMA_PRIVATE,

    /**
     * {@code DMA_ASYNC_TX = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DMA_ASYNC_TX"
    )
    DMA_ASYNC_TX,

    /**
     * {@code DMA_SLAVE = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DMA_SLAVE"
    )
    DMA_SLAVE,

    /**
     * {@code DMA_CYCLIC = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DMA_CYCLIC"
    )
    DMA_CYCLIC,

    /**
     * {@code DMA_INTERLEAVE = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DMA_INTERLEAVE"
    )
    DMA_INTERLEAVE,

    /**
     * {@code DMA_COMPLETION_NO_ORDER = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DMA_COMPLETION_NO_ORDER"
    )
    DMA_COMPLETION_NO_ORDER,

    /**
     * {@code DMA_REPEAT = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DMA_REPEAT"
    )
    DMA_REPEAT,

    /**
     * {@code DMA_LOAD_EOT = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DMA_LOAD_EOT"
    )
    DMA_LOAD_EOT,

    /**
     * {@code DMA_TX_TYPE_END = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DMA_TX_TYPE_END"
    )
    DMA_TX_TYPE_END
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_status"
  )
  public enum dma_status implements Enum<dma_status>, TypedEnum<dma_status, java.lang. @Unsigned Integer> {
    /**
     * {@code DMA_COMPLETE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DMA_COMPLETE"
    )
    DMA_COMPLETE,

    /**
     * {@code DMA_IN_PROGRESS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DMA_IN_PROGRESS"
    )
    DMA_IN_PROGRESS,

    /**
     * {@code DMA_PAUSED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DMA_PAUSED"
    )
    DMA_PAUSED,

    /**
     * {@code DMA_ERROR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DMA_ERROR"
    )
    DMA_ERROR,

    /**
     * {@code DMA_OUT_OF_ORDER = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DMA_OUT_OF_ORDER"
    )
    DMA_OUT_OF_ORDER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_transfer_direction"
  )
  public enum dma_transfer_direction implements Enum<dma_transfer_direction>, TypedEnum<dma_transfer_direction, java.lang. @Unsigned Integer> {
    /**
     * {@code DMA_MEM_TO_MEM = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DMA_MEM_TO_MEM"
    )
    DMA_MEM_TO_MEM,

    /**
     * {@code DMA_MEM_TO_DEV = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DMA_MEM_TO_DEV"
    )
    DMA_MEM_TO_DEV,

    /**
     * {@code DMA_DEV_TO_MEM = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DMA_DEV_TO_MEM"
    )
    DMA_DEV_TO_MEM,

    /**
     * {@code DMA_DEV_TO_DEV = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DMA_DEV_TO_DEV"
    )
    DMA_DEV_TO_DEV,

    /**
     * {@code DMA_TRANS_NONE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DMA_TRANS_NONE"
    )
    DMA_TRANS_NONE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_interleaved_template"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_interleaved_template extends Struct {
    public @Unsigned @OriginalName("dma_addr_t") long src_start;

    public @Unsigned @OriginalName("dma_addr_t") long dst_start;

    public dma_transfer_direction dir;

    public boolean src_inc;

    public boolean dst_inc;

    public boolean src_sgl;

    public boolean dst_sgl;

    public @Unsigned long numf;

    public @Unsigned long frame_size;

    public data_chunk @Size(0) [] sgl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_vec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_vec extends Struct {
    public @Unsigned @OriginalName("dma_addr_t") long addr;

    public @Unsigned long len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_ctrl_flags"
  )
  public enum dma_ctrl_flags implements Enum<dma_ctrl_flags>, TypedEnum<dma_ctrl_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code DMA_PREP_INTERRUPT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DMA_PREP_INTERRUPT"
    )
    DMA_PREP_INTERRUPT,

    /**
     * {@code DMA_CTRL_ACK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DMA_CTRL_ACK"
    )
    DMA_CTRL_ACK,

    /**
     * {@code DMA_PREP_PQ_DISABLE_P = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DMA_PREP_PQ_DISABLE_P"
    )
    DMA_PREP_PQ_DISABLE_P,

    /**
     * {@code DMA_PREP_PQ_DISABLE_Q = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DMA_PREP_PQ_DISABLE_Q"
    )
    DMA_PREP_PQ_DISABLE_Q,

    /**
     * {@code DMA_PREP_CONTINUE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DMA_PREP_CONTINUE"
    )
    DMA_PREP_CONTINUE,

    /**
     * {@code DMA_PREP_FENCE = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DMA_PREP_FENCE"
    )
    DMA_PREP_FENCE,

    /**
     * {@code DMA_CTRL_REUSE = 64}
     */
    @EnumMember(
        value = 64L,
        name = "DMA_CTRL_REUSE"
    )
    DMA_CTRL_REUSE,

    /**
     * {@code DMA_PREP_CMD = 128}
     */
    @EnumMember(
        value = 128L,
        name = "DMA_PREP_CMD"
    )
    DMA_PREP_CMD,

    /**
     * {@code DMA_PREP_REPEAT = 256}
     */
    @EnumMember(
        value = 256L,
        name = "DMA_PREP_REPEAT"
    )
    DMA_PREP_REPEAT,

    /**
     * {@code DMA_PREP_LOAD_EOT = 512}
     */
    @EnumMember(
        value = 512L,
        name = "DMA_PREP_LOAD_EOT"
    )
    DMA_PREP_LOAD_EOT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int bits[1]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_cap_mask_t extends Struct {
    public @Unsigned long @Size(1) [] bits;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_desc_metadata_mode"
  )
  public enum dma_desc_metadata_mode implements Enum<dma_desc_metadata_mode>, TypedEnum<dma_desc_metadata_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code DESC_METADATA_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DESC_METADATA_NONE"
    )
    DESC_METADATA_NONE,

    /**
     * {@code DESC_METADATA_CLIENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DESC_METADATA_CLIENT"
    )
    DESC_METADATA_CLIENT,

    /**
     * {@code DESC_METADATA_ENGINE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DESC_METADATA_ENGINE"
    )
    DESC_METADATA_ENGINE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_chan_percpu"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_chan_percpu extends Struct {
    public @Unsigned long memcpy_count;

    public @Unsigned long bytes_transferred;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_router"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_router extends Struct {
    public Ptr<device> dev;

    public Ptr<?> route_free;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_device extends Struct {
    public kref ref;

    public @Unsigned int chancnt;

    public @Unsigned int privatecnt;

    public list_head channels;

    public list_head global_node;

    public dma_filter filter;

    public dma_cap_mask_t cap_mask;

    public dma_desc_metadata_mode desc_metadata_modes;

    public @Unsigned short max_xor;

    public @Unsigned short max_pq;

    public dmaengine_alignment copy_align;

    public dmaengine_alignment xor_align;

    public dmaengine_alignment pq_align;

    public dmaengine_alignment fill_align;

    public int dev_id;

    public Ptr<device> dev;

    public Ptr<module> owner;

    public ida chan_ida;

    public @Unsigned int src_addr_widths;

    public @Unsigned int dst_addr_widths;

    public @Unsigned int directions;

    public @Unsigned int min_burst;

    public @Unsigned int max_burst;

    public @Unsigned int max_sg_burst;

    public boolean descriptor_reuse;

    public dma_residue_granularity residue_granularity;

    public Ptr<?> device_alloc_chan_resources;

    public Ptr<?> device_router_config;

    public Ptr<?> device_free_chan_resources;

    public Ptr<?> device_prep_dma_memcpy;

    public Ptr<?> device_prep_dma_xor;

    public Ptr<?> device_prep_dma_xor_val;

    public Ptr<?> device_prep_dma_pq;

    public Ptr<?> device_prep_dma_pq_val;

    public Ptr<?> device_prep_dma_memset;

    public Ptr<?> device_prep_dma_memset_sg;

    public Ptr<?> device_prep_dma_interrupt;

    public Ptr<?> device_prep_peripheral_dma_vec;

    public Ptr<?> device_prep_slave_sg;

    public Ptr<?> device_prep_dma_cyclic;

    public Ptr<?> device_prep_interleaved_dma;

    public Ptr<?> device_caps;

    public Ptr<?> device_config;

    public Ptr<?> device_pause;

    public Ptr<?> device_resume;

    public Ptr<?> device_terminate_all;

    public Ptr<?> device_synchronize;

    public Ptr<?> device_tx_status;

    public Ptr<?> device_issue_pending;

    public Ptr<?> device_release;

    public Ptr<?> dbg_summary_show;

    public Ptr<dentry> dbg_dev_root;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_chan_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_chan_dev extends Struct {
    public Ptr<dma_chan> chan;

    public device device;

    public int dev_id;

    public boolean chan_dma_dev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_slave_buswidth"
  )
  public enum dma_slave_buswidth implements Enum<dma_slave_buswidth>, TypedEnum<dma_slave_buswidth, java.lang. @Unsigned Integer> {
    /**
     * {@code DMA_SLAVE_BUSWIDTH_UNDEFINED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DMA_SLAVE_BUSWIDTH_UNDEFINED"
    )
    DMA_SLAVE_BUSWIDTH_UNDEFINED,

    /**
     * {@code DMA_SLAVE_BUSWIDTH_1_BYTE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DMA_SLAVE_BUSWIDTH_1_BYTE"
    )
    DMA_SLAVE_BUSWIDTH_1_BYTE,

    /**
     * {@code DMA_SLAVE_BUSWIDTH_2_BYTES = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DMA_SLAVE_BUSWIDTH_2_BYTES"
    )
    DMA_SLAVE_BUSWIDTH_2_BYTES,

    /**
     * {@code DMA_SLAVE_BUSWIDTH_3_BYTES = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DMA_SLAVE_BUSWIDTH_3_BYTES"
    )
    DMA_SLAVE_BUSWIDTH_3_BYTES,

    /**
     * {@code DMA_SLAVE_BUSWIDTH_4_BYTES = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DMA_SLAVE_BUSWIDTH_4_BYTES"
    )
    DMA_SLAVE_BUSWIDTH_4_BYTES,

    /**
     * {@code DMA_SLAVE_BUSWIDTH_8_BYTES = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DMA_SLAVE_BUSWIDTH_8_BYTES"
    )
    DMA_SLAVE_BUSWIDTH_8_BYTES,

    /**
     * {@code DMA_SLAVE_BUSWIDTH_16_BYTES = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DMA_SLAVE_BUSWIDTH_16_BYTES"
    )
    DMA_SLAVE_BUSWIDTH_16_BYTES,

    /**
     * {@code DMA_SLAVE_BUSWIDTH_32_BYTES = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DMA_SLAVE_BUSWIDTH_32_BYTES"
    )
    DMA_SLAVE_BUSWIDTH_32_BYTES,

    /**
     * {@code DMA_SLAVE_BUSWIDTH_64_BYTES = 64}
     */
    @EnumMember(
        value = 64L,
        name = "DMA_SLAVE_BUSWIDTH_64_BYTES"
    )
    DMA_SLAVE_BUSWIDTH_64_BYTES,

    /**
     * {@code DMA_SLAVE_BUSWIDTH_128_BYTES = 128}
     */
    @EnumMember(
        value = 128L,
        name = "DMA_SLAVE_BUSWIDTH_128_BYTES"
    )
    DMA_SLAVE_BUSWIDTH_128_BYTES
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_slave_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_slave_config extends Struct {
    public dma_transfer_direction direction;

    public @Unsigned @OriginalName("phys_addr_t") long src_addr;

    public @Unsigned @OriginalName("phys_addr_t") long dst_addr;

    public dma_slave_buswidth src_addr_width;

    public dma_slave_buswidth dst_addr_width;

    public @Unsigned int src_maxburst;

    public @Unsigned int dst_maxburst;

    public @Unsigned int src_port_window_size;

    public @Unsigned int dst_port_window_size;

    public boolean device_fc;

    public Ptr<?> peripheral_config;

    public @Unsigned long peripheral_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_residue_granularity"
  )
  public enum dma_residue_granularity implements Enum<dma_residue_granularity>, TypedEnum<dma_residue_granularity, java.lang. @Unsigned Integer> {
    /**
     * {@code DMA_RESIDUE_GRANULARITY_DESCRIPTOR = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DMA_RESIDUE_GRANULARITY_DESCRIPTOR"
    )
    DMA_RESIDUE_GRANULARITY_DESCRIPTOR,

    /**
     * {@code DMA_RESIDUE_GRANULARITY_SEGMENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DMA_RESIDUE_GRANULARITY_SEGMENT"
    )
    DMA_RESIDUE_GRANULARITY_SEGMENT,

    /**
     * {@code DMA_RESIDUE_GRANULARITY_BURST = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DMA_RESIDUE_GRANULARITY_BURST"
    )
    DMA_RESIDUE_GRANULARITY_BURST
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_slave_caps"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_slave_caps extends Struct {
    public @Unsigned int src_addr_widths;

    public @Unsigned int dst_addr_widths;

    public @Unsigned int directions;

    public @Unsigned int min_burst;

    public @Unsigned int max_burst;

    public @Unsigned int max_sg_burst;

    public boolean cmd_pause;

    public boolean cmd_resume;

    public boolean cmd_terminate;

    public dma_residue_granularity residue_granularity;

    public boolean descriptor_reuse;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_descriptor_metadata_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_descriptor_metadata_ops extends Struct {
    public Ptr<?> attach;

    public Ptr<?> get_ptr;

    public Ptr<?> set_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_async_tx_descriptor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_async_tx_descriptor extends Struct {
    public @OriginalName("dma_cookie_t") int cookie;

    public dma_ctrl_flags flags;

    public @Unsigned @OriginalName("dma_addr_t") long phys;

    public Ptr<dma_chan> chan;

    public Ptr<?> tx_submit;

    public Ptr<?> desc_free;

    public @OriginalName("dma_async_tx_callback") Ptr<?> callback;

    public @OriginalName("dma_async_tx_callback_result") Ptr<?> callback_result;

    public Ptr<?> callback_param;

    public Ptr<dmaengine_unmap_data> unmap;

    public dma_desc_metadata_mode desc_metadata_mode;

    public Ptr<dma_descriptor_metadata_ops> metadata_ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_tx_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_tx_state extends Struct {
    public @OriginalName("dma_cookie_t") int last;

    public @OriginalName("dma_cookie_t") int used;

    public @Unsigned int residue;

    public @Unsigned int in_flight_bytes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_slave_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_slave_map extends Struct {
    public String devname;

    public String slave;

    public Ptr<?> param;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_filter extends Struct {
    public @OriginalName("dma_filter_fn") Ptr<?> fn;

    public int mapcnt;

    public Ptr<dma_slave_map> map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_chan_tbl_ent"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_chan_tbl_ent extends Struct {
    public Ptr<dma_chan> chan;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_pte"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_pte extends Struct {
    public @Unsigned long val;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_sgt_handle"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_sgt_handle extends Struct {
    public sg_table sgt;

    public Ptr<Ptr<page>> pages;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_buf_export_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_buf_export_info extends Struct {
    public String exp_name;

    public Ptr<module> owner;

    public Ptr<dma_buf_ops> ops;

    public @Unsigned long size;

    public int flags;

    public Ptr<dma_resv> resv;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_fence_unwrap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_fence_unwrap extends Struct {
    public Ptr<dma_fence> chain;

    public Ptr<dma_fence> array;

    public @Unsigned int index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_resv_usage"
  )
  public enum dma_resv_usage implements Enum<dma_resv_usage>, TypedEnum<dma_resv_usage, java.lang. @Unsigned Integer> {
    /**
     * {@code DMA_RESV_USAGE_KERNEL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DMA_RESV_USAGE_KERNEL"
    )
    DMA_RESV_USAGE_KERNEL,

    /**
     * {@code DMA_RESV_USAGE_WRITE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DMA_RESV_USAGE_WRITE"
    )
    DMA_RESV_USAGE_WRITE,

    /**
     * {@code DMA_RESV_USAGE_READ = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DMA_RESV_USAGE_READ"
    )
    DMA_RESV_USAGE_READ,

    /**
     * {@code DMA_RESV_USAGE_BOOKKEEP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DMA_RESV_USAGE_BOOKKEEP"
    )
    DMA_RESV_USAGE_BOOKKEEP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_resv_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_resv_iter extends Struct {
    public Ptr<dma_resv> obj;

    public dma_resv_usage usage;

    public Ptr<dma_fence> fence;

    public dma_resv_usage fence_usage;

    public @Unsigned int index;

    public Ptr<dma_resv_list> fences;

    public @Unsigned int num_fences;

    public boolean is_restarted;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_buf_sync"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_buf_sync extends Struct {
    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_buf_export_sync_file"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_buf_export_sync_file extends Struct {
    public @Unsigned int flags;

    public int fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_buf_import_sync_file"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_buf_import_sync_file extends Struct {
    public @Unsigned int flags;

    public int fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum dma_fence_flag_bits"
  )
  public enum dma_fence_flag_bits implements Enum<dma_fence_flag_bits>, TypedEnum<dma_fence_flag_bits, java.lang. @Unsigned Integer> {
    /**
     * {@code DMA_FENCE_FLAG_SEQNO64_BIT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DMA_FENCE_FLAG_SEQNO64_BIT"
    )
    DMA_FENCE_FLAG_SEQNO64_BIT,

    /**
     * {@code DMA_FENCE_FLAG_SIGNALED_BIT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DMA_FENCE_FLAG_SIGNALED_BIT"
    )
    DMA_FENCE_FLAG_SIGNALED_BIT,

    /**
     * {@code DMA_FENCE_FLAG_TIMESTAMP_BIT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DMA_FENCE_FLAG_TIMESTAMP_BIT"
    )
    DMA_FENCE_FLAG_TIMESTAMP_BIT,

    /**
     * {@code DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT"
    )
    DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT,

    /**
     * {@code DMA_FENCE_FLAG_USER_BITS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DMA_FENCE_FLAG_USER_BITS"
    )
    DMA_FENCE_FLAG_USER_BITS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_fence_array_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_fence_array_cb extends Struct {
    public dma_fence_cb cb;

    public Ptr<dma_fence_array> array;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_fence_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_fence_array extends Struct {
    public dma_fence base;

    public @OriginalName("spinlock_t") spinlock lock;

    public @Unsigned int num_fences;

    public atomic_t num_pending;

    public Ptr<Ptr<dma_fence>> fences;

    public irq_work work;

    public dma_fence_array_cb @Size(0) [] callbacks;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_fence_chain"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_fence_chain extends Struct {
    public dma_fence base;

    public Ptr<dma_fence> prev;

    public @Unsigned long prev_seqno;

    public Ptr<dma_fence> fence;

    @InlineUnion(46350)
    public dma_fence_cb cb;

    @InlineUnion(46350)
    public irq_work work;

    public @OriginalName("spinlock_t") spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_resv_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_resv_list extends Struct {
    public callback_head rcu;

    public @Unsigned int num_fences;

    public @Unsigned int max_fences;

    public Ptr<dma_fence> @Size(0) [] table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_heap_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_heap_ops extends Struct {
    public Ptr<?> allocate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_heap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_heap extends Struct {
    public String name;

    public Ptr<dma_heap_ops> ops;

    public Ptr<?> priv;

    public @Unsigned @OriginalName("dev_t") int heap_devt;

    public list_head list;

    public cdev heap_cdev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_heap_export_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_heap_export_info extends Struct {
    public String name;

    public Ptr<dma_heap_ops> ops;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_heap_allocation_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_heap_allocation_data extends Struct {
    public @Unsigned long len;

    public @Unsigned int fd;

    public @Unsigned int fd_flags;

    public @Unsigned long heap_flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct dma_heap_attachment"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class dma_heap_attachment extends Struct {
    public Ptr<device> dev;

    public sg_table table;

    public list_head list;

    public boolean mapped;
  }
}
