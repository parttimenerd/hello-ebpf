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
 * Generated class for BPF runtime types that start with blk
 */
@java.lang.SuppressWarnings("unused")
public final class BlkDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction("__blk_add_trace($arg1, $arg2, $arg3, (const unsigned int)$arg4, $arg5, $arg6, $arg7, $arg8, $arg9)")
  public static void __blk_add_trace(Ptr<blk_trace> bt,
      @Unsigned @OriginalName("sector_t") long sector, int bytes,
      @Unsigned @OriginalName("blk_opf_t") int opf, @Unsigned int what, int error, int pdu_len,
      Ptr<?> pdu_data, @Unsigned long cgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<gendisk> __blk_alloc_disk(Ptr<queue_limits> lim, int node,
      Ptr<lock_class_key> lkclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __blk_crypto_bio_prep(Ptr<Ptr<bio>> bio_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__blk_crypto_cfg_supported($arg1, (const struct blk_crypto_config *)$arg2)")
  public static boolean __blk_crypto_cfg_supported(Ptr<blk_crypto_profile> profile,
      Ptr<blk_crypto_config> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__blk_crypto_evict_key($arg1, (const struct blk_crypto_key *)$arg2)")
  public static int __blk_crypto_evict_key(Ptr<blk_crypto_profile> profile,
      Ptr<blk_crypto_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_crypto_free_request(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __blk_crypto_rq_bio_prep(Ptr<request> rq, Ptr<bio> bio,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("blk_status_t") char __blk_crypto_rq_get_keyslot(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_crypto_rq_put_keyslot(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_flush_plug(Ptr<blk_plug> plug, boolean from_schedule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __blk_freeze_queue_start(Ptr<request_queue> q, Ptr<task_struct> owner) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __blk_mark_disk_dead(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<gendisk> __blk_mq_alloc_disk(Ptr<blk_mq_tag_set> set, Ptr<queue_limits> lim,
      Ptr<?> queuedata, Ptr<lock_class_key> lkclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __blk_mq_alloc_driver_tag(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __blk_mq_alloc_map_and_rqs(Ptr<blk_mq_tag_set> set, int hctx_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<request> __blk_mq_alloc_requests(Ptr<blk_mq_alloc_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<request> __blk_mq_alloc_requests_batch(Ptr<blk_mq_alloc_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_complete_request_remote(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __blk_mq_debugfs_rq_show(Ptr<seq_file> m, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __blk_mq_do_dispatch_sched(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_end_request(Ptr<request> rq,
      @OriginalName("blk_status_t") char error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_free_map_and_rqs(Ptr<blk_mq_tag_set> set, @Unsigned int hctx_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_free_request(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __blk_mq_get_tag(Ptr<blk_mq_alloc_data> data, Ptr<sbitmap_queue> bt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("blk_status_t") char __blk_mq_issue_directly(Ptr<blk_mq_hw_ctx> hctx,
      Ptr<request> rq, boolean last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_realloc_hw_ctxs(Ptr<blk_mq_tag_set> set, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_remove_cpuhp(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_requeue_request(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __blk_mq_sched_dispatch_requests(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_sched_restart(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_tag_busy(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_tag_idle(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __blk_mq_unfreeze_queue(Ptr<request_queue> q, boolean force_atomic) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __blk_mq_update_nr_hw_queues(Ptr<blk_mq_tag_set> set, int nr_hw_queues) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __blk_rq_map_sg(Ptr<request> rq, Ptr<scatterlist> sglist,
      Ptr<Ptr<scatterlist>> last_sg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean __blk_throtl_bio(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__blk_trace_note_message($arg1, $arg2, (const u8 *)$arg3, $arg4_)")
  public static void __blk_trace_note_message(Ptr<blk_trace> bt, Ptr<cgroup_subsys_state> css,
      String fmt, java.lang.Object... param3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_abort_request(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_account_io_completion(Ptr<request> req, @Unsigned int bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_account_io_done(Ptr<request> req, @Unsigned long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_account_io_merge_bio(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_account_io_start(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_driver_data(Ptr<request> rq, Ptr<?> data, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_add_partitions(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_rq_to_plug(Ptr<blk_plug> plug, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_timer(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_bio_backmerge(Ptr<?> ignore, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_bio_complete(Ptr<?> ignore, Ptr<request_queue> q, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_bio_frontmerge(Ptr<?> ignore, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_bio_queue(Ptr<?> ignore, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_bio_remap(Ptr<?> ignore, Ptr<bio> bio,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("sector_t") long from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_getrq(Ptr<?> ignore, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_plug(Ptr<?> ignore, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_rq(Ptr<request> rq, @OriginalName("blk_status_t") char error,
      @Unsigned int nr_bytes, @Unsigned int what, @Unsigned long cgid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_rq_complete(Ptr<?> ignore, Ptr<request> rq,
      @OriginalName("blk_status_t") char error, @Unsigned int nr_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_rq_insert(Ptr<?> ignore, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_rq_issue(Ptr<?> ignore, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_rq_merge(Ptr<?> ignore, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_rq_remap(Ptr<?> ignore, Ptr<request> rq,
      @Unsigned @OriginalName("dev_t") int dev, @Unsigned @OriginalName("sector_t") long from) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_rq_requeue(Ptr<?> ignore, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_split(Ptr<?> ignore, Ptr<bio> bio, @Unsigned int pdu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_add_trace_unplug(Ptr<?> ignore, Ptr<request_queue> q, @Unsigned int depth,
      boolean explicit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bio> blk_alloc_discard_bio(Ptr<block_device> bdev,
      Ptr<java.lang. @Unsigned @OriginalName("sector_t") Long> sector,
      Ptr<java.lang. @Unsigned @OriginalName("sector_t") Long> nr_sects,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_alloc_ext_minor() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<blk_flush_queue> blk_alloc_flush_queue(int node, int cmd_size,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<request_queue> blk_alloc_queue(Ptr<queue_limits> lim, int node_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<blk_queue_stats> blk_alloc_queue_stats() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_apply_bdi_limits(Ptr<backing_dev_info> bdi, Ptr<queue_limits> lim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static bio_merge_status blk_attempt_bio_merge(Ptr<request_queue> q, Ptr<request> rq,
      Ptr<bio> bio, @Unsigned int nr_segs, boolean sched_allow_merge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_attempt_plug_merge(Ptr<request_queue> q, Ptr<bio> bio,
      @Unsigned int nr_segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_attempt_req_merge(Ptr<request_queue> q, Ptr<request> rq,
      Ptr<request> next) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_bio_list_merge(Ptr<request_queue> q, Ptr<list_head> list, Ptr<bio> bio,
      @Unsigned int nr_segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_cgroup_bio_start(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_cgroup_congested() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<blk_plug_cb> blk_check_plugged(@OriginalName("blk_plug_cb_fn") Ptr<?> unplug,
      Ptr<?> data, int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_clear_pm_only(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_cmd_complete(Ptr<io_uring_cmd> cmd, @Unsigned int issue_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_complete_request(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_create_buf_file_callback((const u8 *)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static Ptr<dentry> blk_create_buf_file_callback(String filename, Ptr<dentry> parent,
      @Unsigned @OriginalName("umode_t") short mode, Ptr<rchan_buf> buf,
      Ptr<java.lang.Integer> is_global) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_crypto_attr_show(Ptr<kobject> kobj,
      Ptr<attribute> attr, String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_config_supported($arg1, (const struct blk_crypto_config *)$arg2)")
  public static boolean blk_crypto_config_supported(Ptr<block_device> bdev,
      Ptr<blk_crypto_config> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_config_supported_natively($arg1, (const struct blk_crypto_config *)$arg2)")
  public static boolean blk_crypto_config_supported_natively(Ptr<block_device> bdev,
      Ptr<blk_crypto_config> cfg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_derive_sw_secret($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int blk_crypto_derive_sw_secret(Ptr<block_device> bdev,
      Ptr<java.lang.Character> eph_key, @Unsigned long eph_key_size,
      Ptr<java.lang.Character> sw_secret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_evict_key($arg1, (const struct blk_crypto_key *)$arg2)")
  public static void blk_crypto_evict_key(Ptr<block_device> bdev, Ptr<blk_crypto_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_crypto_fallback_alloc_cipher_req(Ptr<blk_crypto_keyslot> slot,
      Ptr<Ptr<skcipher_request>> ciph_req_ret, Ptr<crypto_wait> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_crypto_fallback_bio_prep(Ptr<Ptr<bio>> bio_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bio> blk_crypto_fallback_clone_bio(Ptr<bio> bio_src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_fallback_decrypt_bio(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_fallback_decrypt_endio(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_crypto_fallback_encrypt_bio(Ptr<Ptr<bio>> bio_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_fallback_encrypt_endio(Ptr<bio> enc_bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_fallback_evict_key((const struct blk_crypto_key *)$arg1)")
  public static int blk_crypto_fallback_evict_key(Ptr<blk_crypto_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_fallback_evict_keyslot(@Unsigned int slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_fallback_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_fallback_keyslot_evict($arg1, (const struct blk_crypto_key *)$arg2, $arg3)")
  public static int blk_crypto_fallback_keyslot_evict(Ptr<blk_crypto_profile> profile,
      Ptr<blk_crypto_key> key, @Unsigned int slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_fallback_keyslot_program($arg1, (const struct blk_crypto_key *)$arg2, $arg3)")
  public static int blk_crypto_fallback_keyslot_program(Ptr<blk_crypto_profile> profile,
      Ptr<blk_crypto_key> key, @Unsigned int slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_crypto_fallback_split_bio_if_needed(Ptr<Ptr<bio>> bio_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_fallback_start_using_mode(blk_crypto_mode_num mode_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_generate_key(Ptr<blk_crypto_profile> profile,
      Ptr<java.lang.Character> lt_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_get_keyslot($arg1, (const struct blk_crypto_key *)$arg2, $arg3)")
  public static @OriginalName("blk_status_t") char blk_crypto_get_keyslot(
      Ptr<blk_crypto_profile> profile, Ptr<blk_crypto_key> key,
      Ptr<Ptr<blk_crypto_keyslot>> slot_ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_has_capabilities((const struct blk_crypto_profile *)$arg1, (const struct blk_crypto_profile *)$arg2)")
  public static boolean blk_crypto_has_capabilities(Ptr<blk_crypto_profile> target,
      Ptr<blk_crypto_profile> reference) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_import_key($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int blk_crypto_import_key(Ptr<blk_crypto_profile> profile,
      Ptr<java.lang.Character> raw_key, @Unsigned long raw_key_size,
      Ptr<java.lang.Character> lt_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_init_key($arg1, (const u8 *)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7)")
  public static int blk_crypto_init_key(Ptr<blk_crypto_key> blk_key,
      Ptr<java.lang.Character> key_bytes, @Unsigned long key_size, blk_crypto_key_type key_type,
      blk_crypto_mode_num crypto_mode, @Unsigned int dun_bytes, @Unsigned int data_unit_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_intersect_capabilities($arg1, (const struct blk_crypto_profile *)$arg2)")
  public static void blk_crypto_intersect_capabilities(Ptr<blk_crypto_profile> parent,
      Ptr<blk_crypto_profile> child) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_ioctl(Ptr<block_device> bdev, @Unsigned int cmd, Ptr<?> argp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_ioctl_generate_key(Ptr<blk_crypto_profile> profile, Ptr<?> argp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_ioctl_import_key(Ptr<blk_crypto_profile> profile, Ptr<?> argp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_ioctl_prepare_key(Ptr<blk_crypto_profile> profile, Ptr<?> argp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short blk_crypto_is_visible(Ptr<kobject> kobj,
      Ptr<attribute> attr, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int blk_crypto_keyslot_index(Ptr<blk_crypto_keyslot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short blk_crypto_mode_is_visible(
      Ptr<kobject> kobj, Ptr<attribute> attr, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_crypto_mode_show(Ptr<blk_crypto_profile> profile,
      Ptr<blk_crypto_attr> attr, String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_prepare_key($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int blk_crypto_prepare_key(Ptr<blk_crypto_profile> profile,
      Ptr<java.lang.Character> lt_key, @Unsigned long lt_key_size,
      Ptr<java.lang.Character> eph_key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_profile_destroy(Ptr<blk_crypto_profile> profile) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_profile_destroy_callback(Ptr<?> profile) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_profile_init(Ptr<blk_crypto_profile> profile,
      @Unsigned int num_slots) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_put_keyslot(Ptr<blk_crypto_keyslot> slot) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_crypto_register(Ptr<blk_crypto_profile> profile, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_reprogram_all_keys(Ptr<blk_crypto_profile> profile) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_start_using_key($arg1, (const struct blk_crypto_key *)$arg2)")
  public static int blk_crypto_start_using_key(Ptr<block_device> bdev, Ptr<blk_crypto_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_sysfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_crypto_sysfs_register(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_crypto_sysfs_unregister(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_crypto_update_capabilities($arg1, (const struct blk_crypto_profile *)$arg2)")
  public static void blk_crypto_update_capabilities(Ptr<blk_crypto_profile> dst,
      Ptr<blk_crypto_profile> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_dev_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_done_softirq() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_dropped_read(Ptr<file> filp, String buffer,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_dump_rq_flags(Ptr<request> rq, String msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static rq_end_io_ret blk_end_sync_rq(Ptr<request> rq,
      @OriginalName("blk_status_t") char ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("blk_status_t") char blk_execute_rq(Ptr<request> rq,
      boolean at_head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_execute_rq_nowait(Ptr<request> rq, boolean at_head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_fill_rwbs(String rwbs, @Unsigned @OriginalName("blk_opf_t") int opf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_finish_plug(Ptr<blk_plug> plug) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_flags_show($arg1, (const long unsigned int)$arg2, (const const u8 **)$arg3, $arg4)")
  public static int blk_flags_show(Ptr<seq_file> m, @Unsigned long flags, Ptr<String> flag_name,
      int flag_name_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_flush_complete_seq(Ptr<request> rq, Ptr<blk_flush_queue> fq,
      @Unsigned int seq, @OriginalName("blk_status_t") char error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_flush_integrity() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_free_ext_minor(@Unsigned int minor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_free_flush_queue(Ptr<blk_flush_queue> fq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_free_queue_rcu(Ptr<callback_head> callback_head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_free_queue_stats(Ptr<blk_queue_stats> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_freeze_queue_start(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_freeze_queue_start_non_owner(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_get_meta_cap(Ptr<block_device> bdev, @Unsigned int cmd,
      Ptr<logical_block_metadata_cap> argp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_get_queue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_hctx_poll(Ptr<request_queue> q, Ptr<blk_mq_hw_ctx> hctx,
      Ptr<io_comp_batch> iob, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_ia_range_nr_sectors_show(
      Ptr<blk_independent_access_range> iar, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_ia_range_sector_show(
      Ptr<blk_independent_access_range> iar, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_ia_range_sysfs_nop_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_ia_range_sysfs_show(Ptr<kobject> kobj,
      Ptr<attribute> attr, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_ia_ranges_sysfs_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("blk_status_t") char blk_insert_cloned_request(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_insert_flush(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_integrity_auto_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_integrity_complete(Ptr<request> rq, @Unsigned int nr_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_integrity_generate(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_integrity_merge_bio(Ptr<request_queue> q, Ptr<request> req,
      Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_integrity_merge_rq(Ptr<request_queue> q, Ptr<request> req,
      Ptr<request> next) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_integrity_prepare(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)blk_integrity_profile_name($arg1))")
  public static String blk_integrity_profile_name(Ptr<blk_integrity> bi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_integrity_verify_iter(Ptr<bio> bio, Ptr<bvec_iter> saved_iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_io_schedule() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_ioc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_iocost_init(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_ioctl_discard(Ptr<block_device> bdev,
      @Unsigned @OriginalName("blk_mode_t") int mode, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_lld_busy(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_log_action($arg1, (const u8 *)$arg2, $arg3)")
  public static void blk_log_action(Ptr<trace_iterator> iter, String act, boolean has_cg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_log_action_classic($arg1, (const u8 *)$arg2, $arg3)")
  public static void blk_log_action_classic(Ptr<trace_iterator> iter, String act, boolean has_cg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_log_dump_pdu($arg1, (const struct trace_entry *)$arg2, $arg3)")
  public static void blk_log_dump_pdu(Ptr<trace_seq> s, Ptr<trace_entry> ent, boolean has_cg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_log_generic($arg1, (const struct trace_entry *)$arg2, $arg3)")
  public static void blk_log_generic(Ptr<trace_seq> s, Ptr<trace_entry> ent, boolean has_cg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_log_plug($arg1, (const struct trace_entry *)$arg2, $arg3)")
  public static void blk_log_plug(Ptr<trace_seq> s, Ptr<trace_entry> ent, boolean has_cg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_log_remap($arg1, (const struct trace_entry *)$arg2, $arg3)")
  public static void blk_log_remap(Ptr<trace_seq> s, Ptr<trace_entry> ent, boolean has_cg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_log_split($arg1, (const struct trace_entry *)$arg2, $arg3)")
  public static void blk_log_split(Ptr<trace_seq> s, Ptr<trace_entry> ent, boolean has_cg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_log_unplug($arg1, (const struct trace_entry *)$arg2, $arg3)")
  public static void blk_log_unplug(Ptr<trace_seq> s, Ptr<trace_entry> ent, boolean has_cg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_log_with_error($arg1, (const struct trace_entry *)$arg2, $arg3)")
  public static void blk_log_with_error(Ptr<trace_seq> s, Ptr<trace_entry> ent, boolean has_cg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_lookup_devt((const u8 *)$arg1, $arg2)")
  public static @Unsigned @OriginalName("dev_t") int blk_lookup_devt(String name, int partno) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_map_iter_next(Ptr<request> req, Ptr<req_iterator> iter,
      Ptr<phys_vec> vec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mark_disk_dead(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_add_hw_queues_cpuhp(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_all_tag_iter(Ptr<blk_mq_tags> tags, Ptr<?> fn, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<blk_mq_hw_ctx> blk_mq_alloc_and_init_hctx(Ptr<blk_mq_tag_set> set,
      Ptr<request_queue> q, int hctx_idx, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<gendisk> blk_mq_alloc_disk_for_queue(Ptr<request_queue> q,
      Ptr<lock_class_key> lkclass) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<blk_mq_hw_ctx> blk_mq_alloc_hctx(Ptr<request_queue> q, Ptr<blk_mq_tag_set> set,
      int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<blk_mq_tags> blk_mq_alloc_map_and_rqs(Ptr<blk_mq_tag_set> set,
      @Unsigned int hctx_idx, @Unsigned int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<request_queue> blk_mq_alloc_queue(Ptr<blk_mq_tag_set> set,
      Ptr<queue_limits> lim, Ptr<?> queuedata) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<request> blk_mq_alloc_request(Ptr<request_queue> q,
      @Unsigned @OriginalName("blk_opf_t") int opf,
      @Unsigned @OriginalName("blk_mq_req_flags_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<request> blk_mq_alloc_request_hctx(Ptr<request_queue> q,
      @Unsigned @OriginalName("blk_opf_t") int opf,
      @Unsigned @OriginalName("blk_mq_req_flags_t") int flags, @Unsigned int hctx_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_alloc_rqs(Ptr<blk_mq_tag_set> set, Ptr<blk_mq_tags> tags,
      @Unsigned int hctx_idx, @Unsigned int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_alloc_sched_ctx_batch(Ptr<xarray> elv_tbl, Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_alloc_sched_res(Ptr<request_queue> q, Ptr<elevator_type> type,
      Ptr<elevator_resources> res, @Unsigned int nr_hw_queues) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_alloc_sched_res_batch(Ptr<xarray> elv_tbl, Ptr<blk_mq_tag_set> set,
      @Unsigned int nr_hw_queues) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<elevator_tags> blk_mq_alloc_sched_tags(Ptr<blk_mq_tag_set> set,
      @Unsigned int nr_hw_queues, @Unsigned int nr_requests) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_alloc_set_map_and_rqs(Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_mq_alloc_sq_tag_set($arg1, (const struct blk_mq_ops *)$arg2, $arg3, $arg4)")
  public static int blk_mq_alloc_sq_tag_set(Ptr<blk_mq_tag_set> set, Ptr<blk_mq_ops> ops,
      @Unsigned int queue_depth, @Unsigned int set_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_alloc_tag_set(Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_cancel_work_sync(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_check_expired(Ptr<request> rq, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_check_in_driver(Ptr<request> rq, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_commit_rqs(Ptr<blk_mq_hw_ctx> hctx, int queued, boolean from_schedule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_complete_request(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_complete_request_remote(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_ctx_sysfs_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_debugfs_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_register(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_register_hctx(Ptr<request_queue> q, Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_register_hctxs(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_register_rqos(Ptr<rq_qos> rqos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_register_sched(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_register_sched_hctx(Ptr<request_queue> q,
      Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_debugfs_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_debugfs_rq_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_debugfs_show(Ptr<seq_file> m, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_tags_show(Ptr<seq_file> m, Ptr<blk_mq_tags> tags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_unregister_hctx(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_unregister_hctxs(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_unregister_rqos(Ptr<rq_qos> rqos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_unregister_sched(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_debugfs_unregister_sched_hctx(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_mq_debugfs_write($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long blk_mq_debugfs_write(Ptr<file> file, String buf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_delay_kick_requeue_list(Ptr<request_queue> q, @Unsigned long msecs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_delay_run_hw_queue(Ptr<blk_mq_hw_ctx> hctx, @Unsigned long msecs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_delay_run_hw_queues(Ptr<request_queue> q, @Unsigned long msecs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<request> blk_mq_dequeue_from_ctx(Ptr<blk_mq_hw_ctx> hctx,
      Ptr<blk_mq_ctx> start) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_destroy_queue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_dispatch_list(Ptr<rq_list> rqs, boolean from_sched) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_dispatch_queue_requests(Ptr<rq_list> rqs, @Unsigned int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_dispatch_rq_list(Ptr<blk_mq_hw_ctx> hctx, Ptr<list_head> list,
      boolean get_budget) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_dispatch_wake(
      Ptr<@OriginalName("wait_queue_entry_t") wait_queue_entry> wait, @Unsigned int mode, int flags,
      Ptr<?> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_do_dispatch_ctx(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_end_request(Ptr<request> rq, @OriginalName("blk_status_t") char error) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_end_request_batch(Ptr<io_comp_batch> iob) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_exit_hctx(Ptr<request_queue> q, Ptr<blk_mq_tag_set> set,
      Ptr<blk_mq_hw_ctx> hctx, @Unsigned int hctx_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_exit_queue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_exit_sched(Ptr<request_queue> q, Ptr<elevator_queue> e) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<request> blk_mq_find_and_get_req(Ptr<blk_mq_tags> tags, @Unsigned int bitnr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_finish_request(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_flush_busy_ctxs(Ptr<blk_mq_hw_ctx> hctx, Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_flush_plug_list(Ptr<blk_plug> plug, boolean from_schedule) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_map_and_rqs(Ptr<blk_mq_tag_set> set, Ptr<blk_mq_tags> tags,
      @Unsigned int hctx_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_plug_rqs(Ptr<blk_plug> plug) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_request(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_rq_map(Ptr<blk_mq_tags> tags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_rqs(Ptr<blk_mq_tag_set> set, Ptr<blk_mq_tags> tags,
      @Unsigned int hctx_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_sched_ctx_batch(Ptr<xarray> elv_tbl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_sched_res(Ptr<elevator_resources> res, Ptr<elevator_type> type,
      Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_sched_res_batch(Ptr<xarray> elv_tbl, Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_sched_tags(Ptr<elevator_tags> et, Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_tag_set(Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_free_tags(Ptr<blk_mq_tags> tags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_freeze_queue_nomemsave(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_freeze_queue_wait(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_freeze_queue_wait_timeout(Ptr<request_queue> q, @Unsigned long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_get_budget_and_tag(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_get_hctx_node(Ptr<blk_mq_tag_set> set, @Unsigned int hctx_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int blk_mq_get_tag(Ptr<blk_mq_alloc_data> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long blk_mq_get_tags(Ptr<blk_mq_alloc_data> data, int nr_tags,
      Ptr<java.lang. @Unsigned Integer> offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_handle_expired(Ptr<request> rq, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_has_request(Ptr<request> rq, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_hctx_has_pending(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_hctx_kobj_init(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_hctx_mark_pending(Ptr<blk_mq_hw_ctx> hctx, Ptr<blk_mq_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_hctx_notify_dead(@Unsigned int cpu, Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_hctx_notify_offline(@Unsigned int cpu, Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_hctx_notify_online(@Unsigned int cpu, Ptr<hlist_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_hctx_set_fq_lock_class(Ptr<blk_mq_hw_ctx> hctx,
      Ptr<lock_class_key> key) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_hw_queue_to_node(Ptr<blk_mq_queue_map> qmap, @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_mq_hw_sysfs_cpus_show(Ptr<blk_mq_hw_ctx> hctx,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_mq_hw_sysfs_nr_reserved_tags_show(
      Ptr<blk_mq_hw_ctx> hctx, String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_mq_hw_sysfs_nr_tags_show(Ptr<blk_mq_hw_ctx> hctx,
      String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_hw_sysfs_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long blk_mq_hw_sysfs_show(Ptr<kobject> kobj,
      Ptr<attribute> attr, String page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_in_driver_rw(Ptr<block_device> part,
      Ptr<java.lang. @Unsigned Integer> inflight) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_init_allocated_queue(Ptr<blk_mq_tag_set> set, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_init_sched(Ptr<request_queue> q, Ptr<elevator_type> e,
      Ptr<elevator_resources> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<blk_mq_tags> blk_mq_init_tags(@Unsigned int total_tags,
      @Unsigned int reserved_tags, @Unsigned int flags, int node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_insert_request(Ptr<request> rq,
      @Unsigned @OriginalName("blk_insert_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_insert_requests(Ptr<blk_mq_hw_ctx> hctx, Ptr<blk_mq_ctx> ctx,
      Ptr<list_head> list, boolean run_queue_async) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_issue_direct(Ptr<rq_list> rqs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_kick_requeue_list(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_map_hw_queues(Ptr<blk_mq_queue_map> qmap, Ptr<device> dev,
      @Unsigned int offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_map_queues(Ptr<blk_mq_queue_map> qmap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_map_swqueue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_mark_tag_wait(Ptr<blk_mq_hw_ctx> hctx, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int blk_mq_num_online_queues(@Unsigned int max_queues) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int blk_mq_num_possible_queues(@Unsigned int max_queues) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_mq_num_queues((const struct cpumask *)$arg1, $arg2)")
  public static @Unsigned int blk_mq_num_queues(Ptr<cpumask> mask, @Unsigned int max_queues) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_poll(Ptr<request_queue> q,
      @Unsigned @OriginalName("blk_qc_t") int cookie, Ptr<io_comp_batch> iob, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_put_rq_ref(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_put_tag(Ptr<blk_mq_tags> tags, Ptr<blk_mq_ctx> ctx, @Unsigned int tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_put_tags(Ptr<blk_mq_tags> tags, Ptr<java.lang.Integer> tag_array,
      int nr_tags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("umode_t") short blk_mq_queue_attr_visible(
      Ptr<kobject> kobj, Ptr<attribute> attr, int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_queue_inflight(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_queue_tag_busy_iter(Ptr<request_queue> q, Ptr<?> fn, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_quiesce_queue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_quiesce_queue_nowait(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_quiesce_tagset(Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_realloc_tag_set_tags(Ptr<blk_mq_tag_set> set, int new_nr_hw_queues) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_register_hctx(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_release(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_remove_hw_queues_cpuhp(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("blk_status_t") char blk_mq_request_issue_directly(Ptr<request> rq,
      boolean last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_requeue_request(Ptr<request> rq, boolean kick_requeue_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_requeue_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int blk_mq_rq_cpu(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_rq_inflight(Ptr<request> rq, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_run_hw_queue(Ptr<blk_mq_hw_ctx> hctx, boolean async) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_run_hw_queues(Ptr<request_queue> q, boolean async) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_run_work_fn(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_sched_bio_merge(Ptr<request_queue> q, Ptr<bio> bio,
      @Unsigned int nr_segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sched_dispatch_requests(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sched_free_rqs(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sched_mark_restart_hctx(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sched_reg_debugfs(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sched_tags_teardown(Ptr<request_queue> q, @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_sched_try_insert_merge(Ptr<request_queue> q, Ptr<request> rq,
      Ptr<list_head> free) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_sched_try_merge(Ptr<request_queue> q, Ptr<bio> bio,
      @Unsigned int nr_segs, Ptr<Ptr<request>> merged_request) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sched_unreg_debugfs(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_start_hw_queue(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_start_hw_queues(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_start_request(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_start_stopped_hw_queue(Ptr<blk_mq_hw_ctx> hctx, boolean async) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_start_stopped_hw_queues(Ptr<request_queue> q, boolean async) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_stop_hw_queue(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_stop_hw_queues(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_submit_bio(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sysfs_deinit(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sysfs_init(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_sysfs_register(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_sysfs_register_hctxs(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sysfs_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sysfs_unregister(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_sysfs_unregister_hctxs(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_tag_resize_shared_tags(Ptr<blk_mq_tag_set> set, @Unsigned int size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_mq_tag_update_depth(Ptr<blk_mq_hw_ctx> hctx, Ptr<Ptr<blk_mq_tags>> tagsptr,
      @Unsigned int tdepth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_tag_update_sched_shared_tags(Ptr<request_queue> q, @Unsigned int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_tag_wakeup_all(Ptr<blk_mq_tags> tags, boolean include_reserve) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_tagset_busy_iter(Ptr<blk_mq_tag_set> tagset, Ptr<?> fn, Ptr<?> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_mq_tagset_count_completed_rqs(Ptr<request> rq, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_tagset_wait_completed_request(Ptr<blk_mq_tag_set> tagset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_timeout_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_try_issue_directly(Ptr<blk_mq_hw_ctx> hctx, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_try_issue_list_directly(Ptr<blk_mq_hw_ctx> hctx, Ptr<list_head> list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_unfreeze_queue_nomemrestore(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_unfreeze_queue_non_owner(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int blk_mq_unique_tag(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_unquiesce_queue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_unquiesce_tagset(Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_unregister_hctx(Ptr<blk_mq_hw_ctx> hctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_update_nr_hw_queues(Ptr<blk_mq_tag_set> set, int nr_hw_queues) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<elevator_tags> blk_mq_update_nr_requests(Ptr<request_queue> q,
      Ptr<elevator_tags> et, @Unsigned int nr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_update_queue_map(Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_update_tag_set_shared(Ptr<blk_mq_tag_set> set, boolean shared) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_wait_quiesce_done(Ptr<blk_mq_tag_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_mq_wake_waiters(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_msg_write($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long blk_msg_write(Ptr<file> filp, String buffer,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bio> blk_next_bio(Ptr<bio> bio, Ptr<block_device> bdev, @Unsigned int nr_pages,
      @Unsigned @OriginalName("blk_opf_t") int opf, @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)blk_op_str($arg1))")
  public static String blk_op_str(req_op op) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_pm_runtime_init(Ptr<request_queue> q, Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_post_runtime_resume(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_post_runtime_suspend(Ptr<request_queue> q, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_pre_runtime_resume(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_pre_runtime_suspend(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_probe_dev(@Unsigned @OriginalName("dev_t") int devt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_put_queue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_queue_enter(Ptr<request_queue> q,
      @Unsigned @OriginalName("blk_mq_req_flags_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_queue_exit(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_queue_flag_clear(@Unsigned int flag, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_queue_flag_set(@Unsigned int flag, Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_queue_release(Ptr<kobject> kobj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_queue_rq_timeout(Ptr<request_queue> q, @Unsigned int timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_queue_start_drain(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_queue_usage_counter_release(Ptr<percpu_ref> ref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int blk_recalc_rq_segments(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_register_queue(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_register_tracepoints() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_remove_buf_file_callback(Ptr<dentry> dentry) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_report_disk_dead(Ptr<gendisk> disk, boolean surprise) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_request_module(@Unsigned @OriginalName("dev_t") int devt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_revalidate_disk_zones(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_revalidate_zone_cb(Ptr<blk_zone> zone, @Unsigned int idx, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_rq_append_bio(Ptr<request> rq, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_rq_count_integrity_sg(Ptr<request_queue> q, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_rq_cur_bytes((const struct request *)$arg1)")
  public static int blk_rq_cur_bytes(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_rq_dma_map_iter_next(Ptr<request> req, Ptr<device> dma_dev,
      Ptr<dma_iova_state> state, Ptr<blk_dma_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_rq_dma_map_iter_start(Ptr<request> req, Ptr<device> dma_dev,
      Ptr<dma_iova_state> state, Ptr<blk_dma_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_rq_init(Ptr<request_queue> q, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_rq_integrity_map_user(Ptr<request> rq, Ptr<?> ubuf,
      @OriginalName("ssize_t") long bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_rq_is_poll(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<bio> blk_rq_map_bio_alloc(Ptr<request> rq, @Unsigned int nr_vecs,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_rq_map_integrity_sg(Ptr<request> rq, Ptr<scatterlist> sglist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_rq_map_kern(Ptr<request> rq, Ptr<?> kbuf, @Unsigned int len,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_rq_map_user(Ptr<request_queue> q, Ptr<request> rq,
      Ptr<rq_map_data> map_data, Ptr<?> ubuf, @Unsigned long len,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_rq_map_user_iov($arg1, $arg2, $arg3, (const struct iov_iter *)$arg4, $arg5)")
  public static int blk_rq_map_user_iov(Ptr<request_queue> q, Ptr<request> rq,
      Ptr<rq_map_data> map_data, Ptr<iov_iter> iter,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_rq_merge_ok(Ptr<request> rq, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_rq_poll(Ptr<request> rq, Ptr<io_comp_batch> iob, @Unsigned int poll_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_rq_prep_clone($arg1, $arg2, $arg3, $arg4, (int (*)(struct bio*, struct bio*, void*))$arg5, $arg6)")
  public static int blk_rq_prep_clone(Ptr<request> rq, Ptr<request> rq_src, Ptr<bio_set> bs,
      @Unsigned @OriginalName("gfp_t") int gfp_mask, Ptr<?> bio_ctr, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_rq_set_mixed_merge(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_rq_stat_add(Ptr<blk_rq_stat> stat, @Unsigned long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_rq_stat_init(Ptr<blk_rq_stat> stat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_rq_stat_sum(Ptr<blk_rq_stat> dst, Ptr<blk_rq_stat> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_rq_timed_out_timer(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long blk_rq_timeout(@Unsigned long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_rq_unmap_user(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_rq_unprep_clone(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_set_default_limits(Ptr<queue_limits> lim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_set_pm_only(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_set_queue_depth(Ptr<request_queue> q, @Unsigned int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_set_stacking_limits(Ptr<queue_limits> lim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_should_throtl(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_softirq_cpu_dead(@Unsigned int cpu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_stack_limits(Ptr<queue_limits> t, Ptr<queue_limits> b,
      @Unsigned @OriginalName("sector_t") long start) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_start_plug(Ptr<blk_plug> plug) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_start_plug_nr_ios(Ptr<blk_plug> plug, @Unsigned short nr_ios) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_stat_add(Ptr<request> rq, @Unsigned long now) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_stat_add_callback(Ptr<request_queue> q, Ptr<blk_stat_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("blk_stat_alloc_callback((void (*)(struct blk_stat_callback*))$arg1, (int (*)(const struct request*))$arg2, $arg3, $arg4)")
  public static Ptr<blk_stat_callback> blk_stat_alloc_callback(Ptr<?> timer_fn, Ptr<?> bucket_fn,
      @Unsigned int buckets, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_stat_disable_accounting(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_stat_enable_accounting(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_stat_free_callback(Ptr<blk_stat_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_stat_free_callback_rcu(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_stat_remove_callback(Ptr<request_queue> q, Ptr<blk_stat_callback> cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_stat_timer_fn(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_status_to_errno(@OriginalName("blk_status_t") char status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)blk_status_to_str($arg1))")
  public static String blk_status_to_str(@OriginalName("blk_status_t") char status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_steal_bios(Ptr<bio_list> list, Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_sync_queue(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_throtl_cancel_bios(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_throtl_dispatch_work_fn(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_throtl_exit(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_throtl_init(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_timeout_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_timeout_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static print_line_t blk_trace_event_print(Ptr<trace_iterator> iter, int flags,
      Ptr<trace_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static print_line_t blk_trace_event_print_binary(Ptr<trace_iterator> iter, int flags,
      Ptr<trace_event> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_trace_free(Ptr<request_queue> q, Ptr<blk_trace> bt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_trace_ioctl(Ptr<block_device> bdev, @Unsigned int cmd, String arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_trace_remove(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long blk_trace_request_get_cgid(Ptr<request> rq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_trace_setup(Ptr<request_queue> q, String name,
      @Unsigned @OriginalName("dev_t") int dev, Ptr<block_device> bdev, String arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_trace_setup_queue(Ptr<request_queue> q, Ptr<block_device> bdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_trace_shutdown(Ptr<request_queue> q) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_trace_startstop(Ptr<request_queue> q, int start) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_tracer_init(Ptr<trace_array> tr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_tracer_print_header(Ptr<seq_file> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static print_line_t blk_tracer_print_line(Ptr<trace_iterator> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_tracer_reset(Ptr<trace_array> tr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_tracer_set_flag(Ptr<trace_array> tr, @Unsigned int old_flags,
      @Unsigned int bit, int set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_tracer_start(Ptr<trace_array> tr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_tracer_stop(Ptr<trace_array> tr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static elv_merge blk_try_merge(Ptr<request> rq, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_unregister_queue(Ptr<gendisk> disk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_update_request(Ptr<request> req,
      @OriginalName("blk_status_t") char error, @Unsigned int nr_bytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_validate_integrity_limits(Ptr<queue_limits> lim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_validate_limits(Ptr<queue_limits> lim) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_zone_append_update_request_bio(Ptr<request> rq, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)blk_zone_cond_str($arg1))")
  public static String blk_zone_cond_str(blk_zone_cond zone_cond) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int blk_zone_issue_zeroout(Ptr<block_device> bdev,
      @Unsigned @OriginalName("sector_t") long sector,
      @Unsigned @OriginalName("sector_t") long nr_sects,
      @Unsigned @OriginalName("gfp_t") int gfp_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_zone_mgmt_bio_endio(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_zone_plug_bio(Ptr<bio> bio, @Unsigned int nr_segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_zone_wplug_bio_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_zone_wplug_handle_write(Ptr<bio> bio, @Unsigned int nr_segs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean blk_zone_wplug_prepare_bio(Ptr<blk_zone_wplug> zwplug, Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_zone_write_plug_bio_endio(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_zone_write_plug_bio_merged(Ptr<bio> bio) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_zone_write_plug_finish_request(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void blk_zone_write_plug_init_request(Ptr<request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_plug"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_plug extends Struct {
    public rq_list mq_list;

    public rq_list cached_rqs;

    public @Unsigned long cur_ktime;

    public @Unsigned short nr_ios;

    public @Unsigned short rq_count;

    public boolean multiple_queues;

    public boolean has_elevator;

    public list_head cb_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_holder_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_holder_ops extends Struct {
    public Ptr<?> mark_dead;

    public Ptr<?> sync;

    public Ptr<?> freeze;

    public Ptr<?> thaw;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_zone"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_zone extends Struct {
    public @Unsigned long start;

    public @Unsigned long len;

    public @Unsigned long wp;

    public char type;

    public char cond;

    public char non_seq;

    public char reset;

    public char @Size(4) [] resv;

    public @Unsigned long capacity;

    public char @Size(24) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_integrity_checksum"
  )
  public enum blk_integrity_checksum implements Enum<blk_integrity_checksum>, TypedEnum<blk_integrity_checksum, java.lang.Boolean> {
    /**
     * {@code BLK_INTEGRITY_CSUM_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BLK_INTEGRITY_CSUM_NONE"
    )
    BLK_INTEGRITY_CSUM_NONE,

    /**
     * {@code BLK_INTEGRITY_CSUM_IP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BLK_INTEGRITY_CSUM_IP"
    )
    BLK_INTEGRITY_CSUM_IP,

    /**
     * {@code BLK_INTEGRITY_CSUM_CRC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BLK_INTEGRITY_CSUM_CRC"
    )
    BLK_INTEGRITY_CSUM_CRC,

    /**
     * {@code BLK_INTEGRITY_CSUM_CRC64 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BLK_INTEGRITY_CSUM_CRC64"
    )
    BLK_INTEGRITY_CSUM_CRC64
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_integrity"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_integrity extends Struct {
    public char flags;

    public blk_integrity_checksum csum_type;

    public char metadata_size;

    public char pi_offset;

    public char interval_exp;

    public char tag_size;

    public char pi_tuple_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_independent_access_ranges"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_independent_access_ranges extends Struct {
    public kobject kobj;

    public boolean sysfs_registered;

    public @Unsigned int nr_ia_ranges;

    public blk_independent_access_range @Size(0) [] ia_range;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_independent_access_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_independent_access_range extends Struct {
    public kobject kobj;

    public @Unsigned @OriginalName("sector_t") long sector;

    public @Unsigned @OriginalName("sector_t") long nr_sectors;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_ops extends Struct {
    public Ptr<?> queue_rq;

    public Ptr<?> commit_rqs;

    public Ptr<?> queue_rqs;

    public Ptr<?> get_budget;

    public Ptr<?> put_budget;

    public Ptr<?> set_rq_budget_token;

    public Ptr<?> get_rq_budget_token;

    public Ptr<?> timeout;

    public Ptr<?> poll;

    public Ptr<?> complete;

    public Ptr<?> init_hctx;

    public Ptr<?> exit_hctx;

    public Ptr<?> init_request;

    public Ptr<?> exit_request;

    public Ptr<?> cleanup_rq;

    public Ptr<?> busy;

    public Ptr<?> map_queues;

    public Ptr<?> show_rq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_unique_id"
  )
  public enum blk_unique_id implements Enum<blk_unique_id>, TypedEnum<blk_unique_id, java.lang. @Unsigned Integer> {
    /**
     * {@code BLK_UID_T10 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BLK_UID_T10"
    )
    BLK_UID_T10,

    /**
     * {@code BLK_UID_EUI64 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BLK_UID_EUI64"
    )
    BLK_UID_EUI64,

    /**
     * {@code BLK_UID_NAA = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BLK_UID_NAA"
    )
    BLK_UID_NAA
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_tags"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_tags extends Struct {
    public @Unsigned int nr_tags;

    public @Unsigned int nr_reserved_tags;

    public @Unsigned int active_queues;

    public sbitmap_queue bitmap_tags;

    public sbitmap_queue breserved_tags;

    public Ptr<Ptr<request>> rqs;

    public Ptr<Ptr<request>> static_rqs;

    public list_head page_list;

    public @OriginalName("spinlock_t") spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_trace"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_trace extends Struct {
    public int trace_state;

    public Ptr<rchan> rchan;

    public Ptr<java.lang. @Unsigned Long> sequence;

    public String msg_data;

    public @Unsigned short act_mask;

    public @Unsigned long start_lba;

    public @Unsigned long end_lba;

    public @Unsigned int pid;

    public @Unsigned int dev;

    public Ptr<dentry> dir;

    public list_head running_list;

    public atomic_t dropped;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_flush_queue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_flush_queue extends Struct {
    public @OriginalName("spinlock_t") spinlock mq_flush_lock;

    public @Unsigned int flush_pending_idx;

    public @Unsigned int flush_running_idx;

    public @OriginalName("blk_status_t") char rq_status;

    public @Unsigned long flush_pending_since;

    public list_head @Size(2) [] flush_queue;

    public @Unsigned long flush_data_in_flight;

    public Ptr<request> flush_rq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_tag_set"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_tag_set extends Struct {
    public Ptr<blk_mq_ops> ops;

    public blk_mq_queue_map @Size(3) [] map;

    public @Unsigned int nr_maps;

    public @Unsigned int nr_hw_queues;

    public @Unsigned int queue_depth;

    public @Unsigned int reserved_tags;

    public @Unsigned int cmd_size;

    public int numa_node;

    public @Unsigned int timeout;

    public @Unsigned int flags;

    public Ptr<?> driver_data;

    public Ptr<Ptr<blk_mq_tags>> tags;

    public Ptr<blk_mq_tags> shared_tags;

    public mutex tag_list_lock;

    public list_head tag_list;

    public Ptr<srcu_struct> srcu;

    public rw_semaphore update_nr_hwq_lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_hw_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_hw_ctx extends Struct {
    public anon_member_of_blk_mq_hw_ctx anon0;

    public delayed_work run_work;

    public @OriginalName("cpumask_var_t") Ptr<cpumask> cpumask;

    public int next_cpu;

    public int next_cpu_batch;

    public @Unsigned long flags;

    public Ptr<?> sched_data;

    public Ptr<request_queue> queue;

    public Ptr<blk_flush_queue> fq;

    public Ptr<?> driver_data;

    public sbitmap ctx_map;

    public Ptr<blk_mq_ctx> dispatch_from;

    public @Unsigned int dispatch_busy;

    public @Unsigned short type;

    public @Unsigned short nr_ctx;

    public Ptr<Ptr<blk_mq_ctx>> ctxs;

    public @OriginalName("spinlock_t") spinlock dispatch_wait_lock;

    public @OriginalName("wait_queue_entry_t") wait_queue_entry dispatch_wait;

    public atomic_t wait_index;

    public Ptr<blk_mq_tags> tags;

    public Ptr<blk_mq_tags> sched_tags;

    public @Unsigned int numa_node;

    public @Unsigned int queue_num;

    public atomic_t nr_active;

    public hlist_node cpuhp_online;

    public hlist_node cpuhp_dead;

    public kobject kobj;

    public Ptr<dentry> debugfs_dir;

    public Ptr<dentry> sched_debugfs_dir;

    public list_head hctx_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_eh_timer_return"
  )
  public enum blk_eh_timer_return implements Enum<blk_eh_timer_return>, TypedEnum<blk_eh_timer_return, java.lang. @Unsigned Integer> {
    /**
     * {@code BLK_EH_DONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BLK_EH_DONE"
    )
    BLK_EH_DONE,

    /**
     * {@code BLK_EH_RESET_TIMER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BLK_EH_RESET_TIMER"
    )
    BLK_EH_RESET_TIMER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_queue_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_queue_map extends Struct {
    public Ptr<java.lang. @Unsigned Integer> mq_map;

    public @Unsigned int nr_queues;

    public @Unsigned int queue_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_queue_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_queue_data extends Struct {
    public Ptr<request> rq;

    public boolean last;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_io_trace"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_io_trace extends Struct {
    public @Unsigned int magic;

    public @Unsigned int sequence;

    public @Unsigned long time;

    public @Unsigned long sector;

    public @Unsigned int bytes;

    public @Unsigned int action;

    public @Unsigned int pid;

    public @Unsigned int device;

    public @Unsigned int cpu;

    public @Unsigned short error;

    public @Unsigned short pdu_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_io_trace_remap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_io_trace_remap extends Struct {
    public @Unsigned @OriginalName("__be32") int device_from;

    public @Unsigned @OriginalName("__be32") int device_to;

    public @Unsigned @OriginalName("__be64") long sector_from;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_user_trace_setup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_user_trace_setup extends Struct {
    public char @Size(32) [] name;

    public @Unsigned short act_mask;

    public @Unsigned int buf_size;

    public @Unsigned int buf_nr;

    public @Unsigned long start_lba;

    public @Unsigned long end_lba;

    public @Unsigned int pid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_crypto_mode_num"
  )
  public enum blk_crypto_mode_num implements Enum<blk_crypto_mode_num>, TypedEnum<blk_crypto_mode_num, java.lang. @Unsigned Integer> {
    /**
     * {@code BLK_ENCRYPTION_MODE_INVALID = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BLK_ENCRYPTION_MODE_INVALID"
    )
    BLK_ENCRYPTION_MODE_INVALID,

    /**
     * {@code BLK_ENCRYPTION_MODE_AES_256_XTS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BLK_ENCRYPTION_MODE_AES_256_XTS"
    )
    BLK_ENCRYPTION_MODE_AES_256_XTS,

    /**
     * {@code BLK_ENCRYPTION_MODE_AES_128_CBC_ESSIV = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BLK_ENCRYPTION_MODE_AES_128_CBC_ESSIV"
    )
    BLK_ENCRYPTION_MODE_AES_128_CBC_ESSIV,

    /**
     * {@code BLK_ENCRYPTION_MODE_ADIANTUM = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BLK_ENCRYPTION_MODE_ADIANTUM"
    )
    BLK_ENCRYPTION_MODE_ADIANTUM,

    /**
     * {@code BLK_ENCRYPTION_MODE_SM4_XTS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BLK_ENCRYPTION_MODE_SM4_XTS"
    )
    BLK_ENCRYPTION_MODE_SM4_XTS,

    /**
     * {@code BLK_ENCRYPTION_MODE_MAX = 5}
     */
    @EnumMember(
        value = 5L,
        name = "BLK_ENCRYPTION_MODE_MAX"
    )
    BLK_ENCRYPTION_MODE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_crypto_key_type"
  )
  public enum blk_crypto_key_type implements Enum<blk_crypto_key_type>, TypedEnum<blk_crypto_key_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BLK_CRYPTO_KEY_TYPE_RAW = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BLK_CRYPTO_KEY_TYPE_RAW"
    )
    BLK_CRYPTO_KEY_TYPE_RAW,

    /**
     * {@code BLK_CRYPTO_KEY_TYPE_HW_WRAPPED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BLK_CRYPTO_KEY_TYPE_HW_WRAPPED"
    )
    BLK_CRYPTO_KEY_TYPE_HW_WRAPPED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_config extends Struct {
    public blk_crypto_mode_num crypto_mode;

    public @Unsigned int data_unit_size;

    public @Unsigned int dun_bytes;

    public blk_crypto_key_type key_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_key extends Struct {
    public blk_crypto_config crypto_cfg;

    public @Unsigned int data_unit_size_bits;

    public @Unsigned int size;

    public char @Size(128) [] bytes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_default_limits"
  )
  public enum blk_default_limits implements Enum<blk_default_limits>, TypedEnum<blk_default_limits, java.lang. @Unsigned Integer> {
    /**
     * {@code BLK_MAX_SEGMENTS = 128}
     */
    @EnumMember(
        value = 128L,
        name = "BLK_MAX_SEGMENTS"
    )
    BLK_MAX_SEGMENTS,

    /**
     * {@code BLK_SAFE_MAX_SECTORS = 255}
     */
    @EnumMember(
        value = 255L,
        name = "BLK_SAFE_MAX_SECTORS"
    )
    BLK_SAFE_MAX_SECTORS,

    /**
     * {@code BLK_MAX_SEGMENT_SIZE = 65536}
     */
    @EnumMember(
        value = 65536L,
        name = "BLK_MAX_SEGMENT_SIZE"
    )
    BLK_MAX_SEGMENT_SIZE,

    /**
     * {@code BLK_SEG_BOUNDARY_MASK = -1}
     */
    @EnumMember(
        value = -1L,
        name = "BLK_SEG_BOUNDARY_MASK"
    )
    BLK_SEG_BOUNDARY_MASK
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_debugfs_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_debugfs_attr extends Struct {
    public String name;

    public @Unsigned @OriginalName("umode_t") short mode;

    public Ptr<?> show;

    public Ptr<?> write;

    public Ptr<seq_operations> seq_ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_ctx extends Struct {
    public anon_member_of_blk_mq_ctx anon0;

    public @Unsigned int cpu;

    public @Unsigned short @Size(3) [] index_hw;

    public Ptr<blk_mq_hw_ctx> @Size(3) [] hctxs;

    public Ptr<request_queue> queue;

    public Ptr<blk_mq_ctxs> ctxs;

    public kobject kobj;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_ctxs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_ctxs extends Struct {
    public kobject kobj;

    public Ptr<blk_mq_ctx> queue_ctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_alloc_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_alloc_data extends Struct {
    public Ptr<request_queue> q;

    public @Unsigned @OriginalName("blk_mq_req_flags_t") int flags;

    public @Unsigned int shallow_depth;

    public @Unsigned @OriginalName("blk_opf_t") int cmd_flags;

    public @Unsigned @OriginalName("req_flags_t") int rq_flags;

    public @Unsigned int nr_tags;

    public Ptr<rq_list> cached_rqs;

    public Ptr<blk_mq_ctx> ctx;

    public Ptr<blk_mq_hw_ctx> hctx;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_plug_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_plug_cb extends Struct {
    public list_head list;

    public @OriginalName("blk_plug_cb_fn") Ptr<?> callback;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_integrity_flags"
  )
  public enum blk_integrity_flags implements Enum<blk_integrity_flags>, TypedEnum<blk_integrity_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code BLK_INTEGRITY_NOVERIFY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BLK_INTEGRITY_NOVERIFY"
    )
    BLK_INTEGRITY_NOVERIFY,

    /**
     * {@code BLK_INTEGRITY_NOGENERATE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BLK_INTEGRITY_NOGENERATE"
    )
    BLK_INTEGRITY_NOGENERATE,

    /**
     * {@code BLK_INTEGRITY_DEVICE_CAPABLE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BLK_INTEGRITY_DEVICE_CAPABLE"
    )
    BLK_INTEGRITY_DEVICE_CAPABLE,

    /**
     * {@code BLK_INTEGRITY_REF_TAG = 8}
     */
    @EnumMember(
        value = 8L,
        name = "BLK_INTEGRITY_REF_TAG"
    )
    BLK_INTEGRITY_REF_TAG,

    /**
     * {@code BLK_INTEGRITY_STACKED = 16}
     */
    @EnumMember(
        value = 16L,
        name = "BLK_INTEGRITY_STACKED"
    )
    BLK_INTEGRITY_STACKED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_rq_wait"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_rq_wait extends Struct {
    public completion done;

    public @OriginalName("blk_status_t") char ret;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_expired_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_expired_data extends Struct {
    public boolean has_timedout_rq;

    public @Unsigned long next;

    public @Unsigned long timeout_start;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_dma_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_dma_iter extends Struct {
    public @Unsigned @OriginalName("dma_addr_t") long addr;

    public @Unsigned int len;

    public @OriginalName("blk_status_t") char status;

    public req_iterator iter;

    public pci_p2pdma_map_state p2pdma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_rq_stat"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_rq_stat extends Struct {
    public @Unsigned long mean;

    public @Unsigned long min;

    public @Unsigned long max;

    public @Unsigned int nr_samples;

    public @Unsigned long batch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_queue_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_queue_stats extends Struct {
    public list_head callbacks;

    public @OriginalName("spinlock_t") spinlock lock;

    public int accounting;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_stat_callback"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_stat_callback extends Struct {
    public list_head list;

    public timer_list timer;

    public Ptr<blk_rq_stat> cpu_stat;

    public Ptr<?> bucket_fn;

    public @Unsigned int buckets;

    public Ptr<blk_rq_stat> stat;

    public Ptr<?> timer_fn;

    public Ptr<?> data;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_mq_hw_ctx_sysfs_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_mq_hw_ctx_sysfs_entry extends Struct {
    public attribute attr;

    public Ptr<?> show;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_iou_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_iou_cmd extends Struct {
    public int res;

    public boolean nowait;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_major_name"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_major_name extends Struct {
    public Ptr<blk_major_name> next;

    public int major;

    public char @Size(16) [] name;

    public Ptr<?> probe;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_ia_range_sysfs_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_ia_range_sysfs_entry extends Struct {
    public attribute attr;

    public Ptr<?> show;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_integrity_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_integrity_iter extends Struct {
    public Ptr<?> prot_buf;

    public Ptr<?> data_buf;

    public @Unsigned @OriginalName("sector_t") long seed;

    public @Unsigned int data_size;

    public @Unsigned short interval;

    public String disk_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_zone_type"
  )
  public enum blk_zone_type implements Enum<blk_zone_type>, TypedEnum<blk_zone_type, java.lang. @Unsigned Integer> {
    /**
     * {@code BLK_ZONE_TYPE_CONVENTIONAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BLK_ZONE_TYPE_CONVENTIONAL"
    )
    BLK_ZONE_TYPE_CONVENTIONAL,

    /**
     * {@code BLK_ZONE_TYPE_SEQWRITE_REQ = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BLK_ZONE_TYPE_SEQWRITE_REQ"
    )
    BLK_ZONE_TYPE_SEQWRITE_REQ,

    /**
     * {@code BLK_ZONE_TYPE_SEQWRITE_PREF = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BLK_ZONE_TYPE_SEQWRITE_PREF"
    )
    BLK_ZONE_TYPE_SEQWRITE_PREF
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_zone_cond"
  )
  public enum blk_zone_cond implements Enum<blk_zone_cond>, TypedEnum<blk_zone_cond, java.lang. @Unsigned Integer> {
    /**
     * {@code BLK_ZONE_COND_NOT_WP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "BLK_ZONE_COND_NOT_WP"
    )
    BLK_ZONE_COND_NOT_WP,

    /**
     * {@code BLK_ZONE_COND_EMPTY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BLK_ZONE_COND_EMPTY"
    )
    BLK_ZONE_COND_EMPTY,

    /**
     * {@code BLK_ZONE_COND_IMP_OPEN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "BLK_ZONE_COND_IMP_OPEN"
    )
    BLK_ZONE_COND_IMP_OPEN,

    /**
     * {@code BLK_ZONE_COND_EXP_OPEN = 3}
     */
    @EnumMember(
        value = 3L,
        name = "BLK_ZONE_COND_EXP_OPEN"
    )
    BLK_ZONE_COND_EXP_OPEN,

    /**
     * {@code BLK_ZONE_COND_CLOSED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "BLK_ZONE_COND_CLOSED"
    )
    BLK_ZONE_COND_CLOSED,

    /**
     * {@code BLK_ZONE_COND_READONLY = 13}
     */
    @EnumMember(
        value = 13L,
        name = "BLK_ZONE_COND_READONLY"
    )
    BLK_ZONE_COND_READONLY,

    /**
     * {@code BLK_ZONE_COND_FULL = 14}
     */
    @EnumMember(
        value = 14L,
        name = "BLK_ZONE_COND_FULL"
    )
    BLK_ZONE_COND_FULL,

    /**
     * {@code BLK_ZONE_COND_OFFLINE = 15}
     */
    @EnumMember(
        value = 15L,
        name = "BLK_ZONE_COND_OFFLINE"
    )
    BLK_ZONE_COND_OFFLINE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_zone_report_flags"
  )
  public enum blk_zone_report_flags implements Enum<blk_zone_report_flags>, TypedEnum<blk_zone_report_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code BLK_ZONE_REP_CAPACITY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "BLK_ZONE_REP_CAPACITY"
    )
    BLK_ZONE_REP_CAPACITY
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_zone_report"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_zone_report extends Struct {
    public @Unsigned long sector;

    public @Unsigned int nr_zones;

    public @Unsigned int flags;

    public blk_zone @Size(0) [] zones;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_zone_range"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_zone_range extends Struct {
    public @Unsigned long sector;

    public @Unsigned long nr_sectors;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_zone_wplug"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_zone_wplug extends Struct {
    public hlist_node node;

    public @OriginalName("refcount_t") refcount_struct ref;

    public @OriginalName("spinlock_t") spinlock lock;

    public @Unsigned int flags;

    public @Unsigned int zone_no;

    public @Unsigned int wp_offset;

    public bio_list bio_list;

    public work_struct bio_work;

    public callback_head callback_head;

    public Ptr<gendisk> disk;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_revalidate_zone_args"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_revalidate_zone_args extends Struct {
    public Ptr<gendisk> disk;

    public Ptr<java.lang. @Unsigned Long> conv_zones_bitmap;

    public @Unsigned int nr_zones;

    public @Unsigned int zone_capacity;

    public @Unsigned int last_zone_capacity;

    public @Unsigned @OriginalName("sector_t") long sector;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_profile"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_profile extends Struct {
    public blk_crypto_ll_ops ll_ops;

    public @Unsigned int max_dun_bytes_supported;

    public @Unsigned int key_types_supported;

    public @Unsigned int @Size(5) [] modes_supported;

    public Ptr<device> dev;

    public @Unsigned int num_slots;

    public rw_semaphore lock;

    public lock_class_key lockdep_key;

    public @OriginalName("wait_queue_head_t") wait_queue_head idle_slots_wait_queue;

    public list_head idle_slots;

    public @OriginalName("spinlock_t") spinlock idle_slots_lock;

    public Ptr<hlist_head> slot_hashtable;

    public @Unsigned int log_slot_ht_size;

    public Ptr<blk_crypto_keyslot> slots;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_import_key_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_import_key_arg extends Struct {
    public @Unsigned long raw_key_ptr;

    public @Unsigned long raw_key_size;

    public @Unsigned long lt_key_ptr;

    public @Unsigned long lt_key_size;

    public @Unsigned long @Size(4) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_generate_key_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_generate_key_arg extends Struct {
    public @Unsigned long lt_key_ptr;

    public @Unsigned long lt_key_size;

    public @Unsigned long @Size(4) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_prepare_key_arg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_prepare_key_arg extends Struct {
    public @Unsigned long lt_key_ptr;

    public @Unsigned long lt_key_size;

    public @Unsigned long eph_key_ptr;

    public @Unsigned long eph_key_size;

    public @Unsigned long @Size(4) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_ll_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_ll_ops extends Struct {
    public Ptr<?> keyslot_program;

    public Ptr<?> keyslot_evict;

    public Ptr<?> derive_sw_secret;

    public Ptr<?> import_key;

    public Ptr<?> generate_key;

    public Ptr<?> prepare_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_mode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_mode extends Struct {
    public String name;

    public String cipher_str;

    public @Unsigned int keysize;

    public @Unsigned int security_strength;

    public @Unsigned int ivsize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_keyslot"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_keyslot extends Struct {
    public atomic_t slot_refs;

    public list_head idle_slot_node;

    public hlist_node hash_node;

    public Ptr<blk_crypto_key> key;

    public Ptr<blk_crypto_profile> profile;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_kobj"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_kobj extends Struct {
    public kobject kobj;

    public Ptr<blk_crypto_profile> profile;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_attr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_attr extends Struct {
    public attribute attr;

    public Ptr<?> show;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_crypto_fallback_keyslot"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_fallback_keyslot extends Struct {
    public blk_crypto_mode_num crypto_mode;

    public Ptr<crypto_skcipher> @Size(5) [] tfms;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union blk_crypto_iv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_crypto_iv extends Union {
    public @Unsigned @OriginalName("__le64") long @Size(4) [] dun;

    public char @Size(32) [] bytes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum blk_req_status"
  )
  public enum blk_req_status implements Enum<blk_req_status>, TypedEnum<blk_req_status, java.lang. @Unsigned Integer> {
    /**
     * {@code REQ_PROCESSING = 0}
     */
    @EnumMember(
        value = 0L,
        name = "REQ_PROCESSING"
    )
    REQ_PROCESSING,

    /**
     * {@code REQ_WAITING = 1}
     */
    @EnumMember(
        value = 1L,
        name = "REQ_WAITING"
    )
    REQ_WAITING,

    /**
     * {@code REQ_DONE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "REQ_DONE"
    )
    REQ_DONE,

    /**
     * {@code REQ_ERROR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "REQ_ERROR"
    )
    REQ_ERROR,

    /**
     * {@code REQ_EOPNOTSUPP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "REQ_EOPNOTSUPP"
    )
    REQ_EOPNOTSUPP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct blk_shadow"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class blk_shadow extends Struct {
    public blkif_request req;

    public Ptr<request> request;

    public Ptr<Ptr<grant>> grants_used;

    public Ptr<Ptr<grant>> indirect_grants;

    public Ptr<scatterlist> sg;

    public @Unsigned int num_sg;

    public blk_req_status status;

    public @Unsigned long associated_id;
  }
}
